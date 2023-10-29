#!/usr/bin/env python3

# Helper script to compare the TTI cost table values for various IR ops and
# intrinsics against the llvm-mca costs reported from the generated assembly.
#
# As cost tables typically use worst case values, the script runs against a set
# of cpus in a similar level and checks the cost reported by opt --analyze vs
# the highest cost across all those cpus.
#
# By default, the script will exhaustively check all cpulevels and all
# scalar/vector ops up to the max legal vector width (pow2 numelts only), but
# more specific checks can be made with the --cpulevel and --op command args.

import argparse
import math
import re
import subprocess


class Error(Exception):
  """Simple exception type for erroring without a traceback."""


def _run_command(cmd, *, op):
  try:
    subprocess.check_call(cmd)
  except subprocess.CalledProcessError as exc:
    raise Error(f"Error running {cmd} : {op}") from exc


def run_analysis(srctype, dsttype, op, opname, cpus, declarations=""):
  costs = {}
  recipthroughputs = {}

  # TODO - stop writing/reading files and just pipe stdout/stdin to the tools
  # TODO - RecipThroughput only - add Latency/CodeSize/SizeAndLatency support

  # Write out candidate IR
  with open("fuzz.ll", "w") as f:
    f.write(
      "\n".join(
        [
          f"define {dsttype} @costfuzz({srctype} %a0, {srctype} %a1, {srctype} %a2) {{",
          'tail call void asm sideeffect "# LLVM-MCA-BEGIN foo", "~{dirflag},~{fpsr},~{flags},~{rsp}"()',
          op,
          'tail call void asm sideeffect "# LLVM-MCA-END foo", "~{dirflag},~{fpsr},~{flags},~{rsp}"()',
          f"ret {dsttype} %result",
          "}",
          declarations,
        ]
      )
    )

  # TODO - is it worth trying to run these in parallel?
  for cpu in cpus:
    # Run cost-model analysis
    _run_command(
      [
        args.opt_binary,
        "-analyze",
        "-cost-model",
        f"-mcpu={cpu}",
        f"-mtriple={args.triple}",
        "fuzz.ll",
        "-S",
        "-o",
        "analyze.txt",
      ],
      op=op,
    )

    # Run llc
    _run_command(
      [
        args.llc_binary,
        f"-mcpu={cpu}",
        f"-mtriple={args.triple}",
        "fuzz.ll",
        "-o",
        "fuzz.s",
      ],
      op=op,
    )

    # TODO - strip out assembly to pass to llvm-mca to avoid need for asm barriers in IR

    # Run llvm-mca
    _run_command(
      [
        args.llvm_mca_binary,
        f"-mcpu={cpu}",
        f"-mtriple={args.triple}",
        "fuzz.s",
        "-o",
        "mca.txt",
      ],
      op=op,
    )

    # Extract costs
    with open("analyze.txt", "r") as f:
      for line in f.readlines():
        if opname in line:
          matches = re.search(
            r"Cost Model: Found an estimated cost of (\d+)", line
          )
          costs[cpu] = float(matches.group(1))
          break

    # Extract mca (worst case cost to use math.ceil() to round up)
    with open("mca.txt", "r") as f:
      for line in f.readlines():
        if "Block RThroughput:" in line:
          matches = re.search(r"Block RThroughput: ([0-9\.]+)", line)
          recipthroughputs[cpu] = math.ceil(
            max(float(1), float(matches.group(1)))
          )
          break

  mincost = min(costs.values())
  maxcost = max(costs.values())
  minrecipthroughput = min(recipthroughputs.values())
  maxrecipthroughput = max(recipthroughputs.values())

  if maxcost != maxrecipthroughput:
    print(
      f"{dsttype} {opname} {srctype}: cost ({mincost} - {maxcost}) vs recipthroughput ({minrecipthroughput} - {maxrecipthroughput})"
    )
    for cpu in cpus:
      print(f"  {cpu} : {costs[cpu]} vs {recipthroughputs[cpu]}")
    if args.stop_on_diff:
      raise SystemExit(-1)


def get_float_string(width):
  if width == 16:
    return "half"
  if width == 32:
    return "float"
  if width == 64:
    return "double"
  return None


def get_type(elementcount, base):
  if elementcount == 0:
    return base
  return f"<{elementcount} x {base}>"


def get_typestub(elttype, elementcount, base):
  if elementcount == 0:
    return f"{elttype}{base}"
  return f"v{elementcount}{elttype}{base}"


def get_typeistub(elementcount, base):
  return get_typestub("i", elementcount, base)


def get_typefstub(elementcount, base):
  return get_typestub("f", elementcount, base)


# TODO - add half conversion
def fp_cast(maxwidth, ops, cpus):
  for op in ops:
    for srcbasewidth in [32, 64]:
      for dstbasewidth in [32, 64]:
        for elementcount in [0, 2, 4, 8, 16, 32, 64]:
          srctype = get_type(elementcount, get_float_string(srcbasewidth))
          dsttype = get_type(elementcount, get_float_string(dstbasewidth))
          cmd = f"%result = {op} {srctype} %a0 to {dsttype}"

          if srcbasewidth < dstbasewidth and op == "fpext":
            if dstbasewidth * elementcount <= maxwidth:
              run_analysis(srctype, dsttype, cmd, op, cpus)

          if srcbasewidth > dstbasewidth and op == "fptrunc":
            if srcbasewidth * elementcount <= maxwidth:
              run_analysis(srctype, dsttype, cmd, op, cpus)


def fp_unaryops(maxwidth, ops, cpus):
  for op in ops:
    for basewidth in [32, 64]:
      for elementcount in [0, 2, 4, 8, 16]:
        if (basewidth * elementcount) <= maxwidth:
          type = get_type(elementcount, get_float_string(basewidth))
          cmd = f"%result = {op} {type} %a0"
          run_analysis(type, type, cmd, op, cpus)


def fp_binops(maxwidth, ops, cpus):
  for op in ops:
    for basewidth in [32, 64]:
      for elementcount in [0, 2, 4, 8, 16]:
        if (basewidth * elementcount) <= maxwidth:
          type = get_type(elementcount, get_float_string(basewidth))
          cmd = f"%result = {op} {type} %a0, %a1"
          run_analysis(type, type, cmd, op, cpus)


# TODO - support bool predicate results for some targets
def fp_cmp(maxwidth, ops, cpus):
  for op in ops:
    for basewidth in [32, 64]:
      for elementcount in [2, 4, 8, 16]:
        if (basewidth * elementcount) <= maxwidth:
          for cc in [ "oeq", "ogt", "oge", "olt", "ole", "one", "ord", "ueq", "ugt", "uge", "ult", "ule", "une", "uno" ]:
            cctype = get_type(elementcount, f"i{1}")
            srctype = get_type(elementcount, get_float_string(basewidth))
            dsttype = get_type(elementcount, f"i{basewidth}")
            cmd = "\n".join(
              [
                f"%cmp = {op} {cc} {srctype} %a0, %a1",
                f"%result = sext {cctype} %cmp to {dsttype}",
              ]
            )
            run_analysis(srctype, dsttype, cmd, f"{op} {cc}", cpus)


def int_cast(maxwidth, ops, cpus):
  for op in ops:
    for srcbasewidth in [8, 16, 32, 64]:
      for dstbasewidth in [8, 16, 32, 64]:
        for elementcount in [0, 2, 4, 8, 16, 32, 64]:
          srctype = get_type(elementcount, f"i{srcbasewidth}")
          dsttype = get_type(elementcount, f"i{dstbasewidth}")
          cmd = f"%result = {op} {srctype} %a0 to {dsttype}"

          if srcbasewidth < dstbasewidth and op != "trunc":
            if dstbasewidth * elementcount <= maxwidth:
              run_analysis(srctype, dsttype, cmd, op, cpus)

          if srcbasewidth > dstbasewidth and op == "trunc":
            if srcbasewidth * elementcount <= maxwidth:
              if elementcount != 0:
                run_analysis(srctype, dsttype, cmd, op, cpus)


def int_binops(maxwidth, ops, cpus):
  for op in ops:
    for basewidth in [8, 16, 32, 64]:
      for elementcount in [0, 2, 4, 8, 16, 32, 64]:
        if (basewidth * elementcount) <= maxwidth:
          type = get_type(elementcount, f"i{basewidth}")
          cmd = f"%result = {op} {type} %a0, %a1"
          run_analysis(type, type, cmd, f" {op} ", cpus)


def int_shifts(maxwidth, ops, cpus):
  for op in ops:
    for basewidth in [8, 16, 32, 64]:
      for elementcount in [0, 2, 4, 8, 16, 32, 64]:
        if (basewidth * elementcount) <= maxwidth:
          type = get_type(elementcount, f"i{basewidth}")
          cmd = f"%result = {op} {type} %a0, %a1"
          run_analysis(type, type, cmd, op, cpus)


# TODO - support bool predicate results for some targets
def int_cmp(maxwidth, ops, cpus):
  for op in ops:
    for basewidth in [8, 16, 32, 64]:
      for elementcount in [2, 4, 8, 16, 32, 64]:
        if (basewidth * elementcount) <= maxwidth:
          for cc in [ "eq", "ne", "ugt", "uge", "ult", "ule", "sgt", "sge", "slt", "sle" ]:
            cctype = get_type(elementcount, f"i{1}")
            type = get_type(elementcount, f"i{basewidth}")
            cmd = "\n".join(
              [
                f"%cmp = {op} {cc} {type} %a0, %a1",
                f"%result = sext {cctype} %cmp to {type}",
              ]
            )
            run_analysis(type, type, cmd, f"{op} {cc}", cpus)


def int_to_fp(maxwidth, ops, cpus):
  for op in ops:
    for srcbasewidth in [32]:
      for dstbasewidth in [32, 64]:
        for elementcount in [0, 2, 4, 8, 16, 32, 64]:
          if (min(srcbasewidth, dstbasewidth) * elementcount) <= maxwidth:
            srctype = get_type(elementcount, f"i{srcbasewidth}")
            dsttype = get_type(elementcount, get_float_string(dstbasewidth))
            cmd = f"%result = {op} {srctype} %a0 to {dsttype}"
            run_analysis(srctype, dsttype, cmd, op, cpus)


def fp_to_int(maxwidth, ops, cpus):
  for op in ops:
    for srcbasewidth in [32, 64]:
      for dstbasewidth in [32]:
        for elementcount in [0, 2, 4, 8, 16, 32, 64]:
          if (min(srcbasewidth, dstbasewidth) * elementcount) <= maxwidth:
            srctype = get_type(elementcount, get_float_string(srcbasewidth))
            dsttype = get_type(elementcount, f"i{dstbasewidth}")
            cmd = f"%result = {op} {srctype} %a0 to {dsttype}"
            run_analysis(srctype, dsttype, cmd, op, cpus)


def int_unaryintrinsics(maxwidth, ops, cpus, boolarg = None):
  for op in ops:
    for basewidth in [8, 16, 32, 64]:
      if op == "bswap" and basewidth == 8:
        continue
      for elementcount in [0, 2, 4, 8, 16, 32, 64]:
        if (basewidth * elementcount) <= maxwidth:
          type = get_type(elementcount, f"i{basewidth}")
          stub = get_typeistub(elementcount, basewidth)
          if boolarg is not None:
            boolval = -1 if boolarg else 0
            cmd = f"%result = call {type} @llvm.{op}.{stub}({type} %a0, i1 {boolval})"
            declaration = f"declare {type} @llvm.{op}.{stub}({type}, i1)"
          else:
            cmd = f"%result = call {type} @llvm.{op}.{stub}({type} %a0)"
            declaration = f"declare {type} @llvm.{op}.{stub}({type})"
          run_analysis(type, type, cmd, op, cpus, declaration)


def int_binaryintrinsics(maxwidth, ops, cpus):
  for op in ops:
    for basewidth in [8, 16, 32, 64]:
      for elementcount in [0, 2, 4, 8, 16, 32, 64]:
        if (basewidth * elementcount) <= maxwidth:
          type = get_type(elementcount, f"i{basewidth}")
          stub = get_typeistub(elementcount, basewidth)
          cmd = f"%result = call {type} @llvm.{op}.{stub}({type} %a0, {type} %a1)"
          declaration = f"declare {type} @llvm.{op}.{stub}({type}, {type})"
          run_analysis(type, type, cmd, op, cpus, declaration)


def int_ternaryintrinsics(maxwidth, ops, cpus):
  for op in ops:
    for basewidth in [8, 16, 32, 64]:
      for elementcount in [0, 2, 4, 8, 16, 32, 64]:
        if (basewidth * elementcount) <= maxwidth:
          type = get_type(elementcount, f"i{basewidth}")
          stub = get_typeistub(elementcount, basewidth)
          cmd = f"%result = call {type} @llvm.{op}.{stub}({type} %a0, {type} %a1, {type} %a2)"
          declaration = f"declare {type} @llvm.{op}.{stub}({type}, {type}, {type})"
          run_analysis(type, type, cmd, op, cpus, declaration)


def int_reductions(maxwidth, ops, cpus):
  for op in ops:
    for basewidth in [8, 16, 32, 64]:
      for elementcount in [2, 4, 8, 16, 32, 64]:
        if (basewidth * elementcount) <= maxwidth:
          vectype = get_type(elementcount, f"i{basewidth}")
          scltype = get_type(0, f"i{basewidth}")
          stub = get_typeistub(elementcount, basewidth)
          cmd = f"%result = call {scltype} @llvm.vector.reduce.{op}.{stub}({vectype} %a0)"
          declaration = f"declare {scltype} @llvm.vector.reduce.{op}.{stub}({vectype})"
          run_analysis(vectype, scltype, cmd, f"vector.reduce.{op}", cpus, declaration)


def filter_ops(targetops, ops):
  if len(targetops) == 0:
    return ops

  selectops = list()
  for targetop in targetops:
    if ops.count(targetop):
      selectops.append(targetop)
  return selectops


def test_cpus(targetops, maxwidth, cpus):
  ops = filter_ops(targetops, ["fpext", "fptrunc"])
  fp_cast(maxwidth, ops, cpus)

  ops = filter_ops(targetops, ["fneg"])
  fp_unaryops(maxwidth, ops, cpus)

  ops = filter_ops(targetops, ["fadd", "fsub", "fmul", "fdiv"])
  fp_binops(maxwidth, ops, cpus)

  ops = filter_ops(targetops, ["fcmp"])
  fp_cmp(maxwidth, ops, cpus)

  ops = filter_ops(targetops, ["select"])
  # TODO - select with fcmp

  # TODO - fabs, fsqrt, ceil, floor, trunc, rint, nearbyint
  # fp_unaryintrinsics()

  # TODO - copysign, maxnum, maxinum, minnum, mininum
  # fp_binaryintrinsics()

  # TODO - reduction op filtering
  # if len(targetops) == 0 or "reduce" in targetops:
  # fp_reductions(maxwidth, [ "fadd", "fmul", "fmax", "fmin" ], cpus)

  ops = filter_ops(targetops, ["sext", "zext", "trunc"])
  int_cast(maxwidth, ops, cpus)

  # TODO - sdiv/udiv/srem/urem (+ by constant/pow2 cases)
  ops = filter_ops(targetops, ["and", "or", "xor", "add", "sub", "mul"])
  int_binops(maxwidth, ops, cpus)

  # TODO - uniform / constant shift amount costs
  ops = filter_ops(targetops, ["shl", "lshr", "ashr"])
  int_shifts(maxwidth, ops, cpus)

  ops = filter_ops(targetops, ["icmp"])
  int_cmp(maxwidth, ops, cpus)

  ops = filter_ops(targetops, ["select"])
  # TODO - select with icmp

  # TODO - bitcasts i1/i32/i64/float/double

  # TODO - vector ops (extract/insert/shuffle)

  # TODO - better reduction op filtering
  if len(targetops) == 0 or "reduce" in targetops:
    int_reductions(
      maxwidth,
      ["and", "or", "xor", "add", "mul", "smax", "smin", "umax", "umin"],
      cpus,
    )

  ops = filter_ops(targetops, ["sitofp", "uitofp"])
  int_to_fp(maxwidth, ops, cpus)

  ops = filter_ops(targetops, ["fptosi", "fptoui"])
  fp_to_int(maxwidth, ops, cpus)

  ops = filter_ops(targetops, ["bitreverse", "bswap", "ctpop"])
  int_unaryintrinsics(maxwidth, ops, cpus)

  ops = filter_ops(targetops, ["ctlz", "cttz"])
  int_unaryintrinsics(maxwidth, ops, cpus, False)
  int_unaryintrinsics(maxwidth, ops, cpus, True)

  ops = filter_ops(targetops, ["smax", "smin", "umax", "umin"])
  int_binaryintrinsics(maxwidth, ops, cpus)

  # TODO - uniform / constant shift amount costs
  ops = filter_ops(targetops, ["fshl", "fshr"])
  int_ternaryintrinsics(maxwidth, ops, cpus)


def main():
  # TODO - 2 modes - (a) create generic codegen for sse level and compare cpu analysis
  #          (b) create generic codegen for each cpu of a similar level and compare cpu analysis
  # TODO - How should we test sandybridge (default) on other levels? What about other cpus?
  cpulevels = {
    "avx512"  : (512, ["skylake-avx512"]),
    "avx512f" : (512, ["knl"]),
    "avx2"    : (256, ["broadwell", "haswell", "skylake", "znver1", "znver2", "znver3"]),
    "avx"     : (256, ["bdver2", "btver2", "sandybridge"]),
    "sse4.2"  : (128, ["slm"]),
    "sse4.1"  : (128, ["slm"]),
    "ssse3"   : (128, ["atom"]),
    "sse3"    : (128, ["atom"]),
    "sse2"    : (128, ["atom"]),
  }

  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument(
    "--triple",
    metavar="<triple>",
    default="x86_64--",
    help="Specify the target triple (default: x86_64--)",
  )
  parser.add_argument(
    "--cpulevel",
    choices=cpulevels.keys(),
    default=None,
    help="Only test cpus specific to a cpulevel",
  )
  # TODO - --op(s) command line handling to select multiple ops for testing
  parser.add_argument(
    "--op", metavar="<op>", default=None, help="Only test requested op"
  )
  parser.add_argument(
    "--stop-on-diff",
    action="store_true",
    help="Stop on first analysis/mca discrepancy, leaves fuzz.ll, analyze.txt, fuzz.s and mca.txt temp files",
  )
  parser.add_argument(
    "--opt-binary",
    metavar="<path>",
    default="opt",
    help='The "opt" binary to use to analyze the test case IR (default: opt)',
  )
  parser.add_argument(
    "--llc-binary",
    metavar="<path>",
    default="llc",
    help='The "llc" binary to use to generate the test case assembly (default: llc)',
  )
  parser.add_argument(
    "--llvm-mca-binary",
    metavar="<path>",
    default="llvm-mca",
    help='The "llvm-mca "binary to use to analyze the test case assembly (default: llvm-mca)',
  )

  global args
  args = parser.parse_args()

  targetops = list()
  if args.op is not None:
    targetops = [args.op]

  targetcpus = ["avx512", "avx2", "avx", "sse4.2", "ssse3"]
  if args.cpulevel is not None:
    targetcpus = [args.cpulevel]

  for targetcpu in targetcpus:
    (maxwidth, cpus) = cpulevels[targetcpu]
    test_cpus(targetops, maxwidth, cpus)

  return 0


if __name__ == "__main__":
  try:
    raise SystemExit(main())
  except Error as error:
    print(f"error: {error}")
    raise SystemExit(1) from error
