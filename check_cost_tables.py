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
from random import randint
import re
import os
import subprocess
import concurrent.futures
from collections import defaultdict

class Error(Exception):
  """Simple exception type for erroring without a traceback."""


def _run_command(cmd, *, input, op):
  try:
    return subprocess.run(cmd, input=input, text=True, capture_output=True)
  except subprocess.CalledProcessError as exc:
    raise Error(f"Error running {cmd} : {op}") from exc


def _run_costmodel(op, opname, ir, cpu, costkind):
  # Run opt to get cost-model report
  analysis = _run_command(
    [
      args.opt_binary,
      "-passes=print<cost-model>",
      "-disable-output",
      f"-cost-kind={costkind}",
      f"-mcpu={cpu}",
      f"-mtriple={args.triple}"
    ],
    input=ir,
    op=op,
  )

  # Extract analyze costs
  for line in analysis.stderr.splitlines():
    if opname in line:
      matches = re.search(
        r"Cost Model: Found an estimated cost of (\d+)", line
      )
      return float(matches.group(1))

  return None


def _run_codegen(op, ir, cpu):
  # Run llc to generate asm
  llc = _run_command(
    [
      args.llc_binary,
      f"-mcpu={cpu}",
      f"-mtriple={args.triple}"
    ],
    input=ir,
    op=op,
  )

  # TODO - strip out assembly to pass to llvm-mca to avoid need for asm barriers in IR

  # Run llvm-mca to determine asm statistics
  mca = _run_command(
    [
      args.llvm_mca_binary,
      f"-mcpu={cpu}",
      f"-mtriple={args.triple}"
    ],
    input=llc.stdout,
    op=op,
  )

  # Extract mca statistics (worst case cost to use math.ceil() to round up)
  costs = {}

  for line in mca.stdout.splitlines():
    if "Instructions:" in line:
      matches = re.search(r"Instructions:      ([0-9]+)", line)
      costs["code-size"] = round(math.ceil(max(float(1), float(matches.group(1)))) / float(100))
      continue
    if "Total Cycles:" in line:
      matches = re.search(r"Total Cycles:      ([0-9]+)", line)
      costs["latency"] = round(math.ceil(max(float(1), float(matches.group(1)))) / float(100))
      continue
    if "Total uOps:" in line:
      matches = re.search(r"Total uOps:        ([0-9]+)", line)
      costs["size-latency"] = round(math.ceil(max(float(1), float(matches.group(1)))) / float(100))
      continue
    if "Block RThroughput:" in line:
      matches = re.search(r"Block RThroughput: ([0-9\.]+)", line)
      costs["throughput"] = math.ceil(max(float(1), float(matches.group(1))))
      break # Assumes other lines are above rthroughput

  if len(costs.keys()) != 4:
    with open("fuzz.ll", "w") as f:
      f.write(ir)
    with open("fuzz.s", "w") as f:
      f.write(llc.stdout)
    raise Error("Failed to parsed mca data {op} for {cpu}")

  return costs


def run_analysis(argsignature, dsttype, op, opname, opdesc, cpus, declaration="", pre = "", post = ""):
  costkinds = [ "throughput", "latency", "code-size", "size-latency" ];

  analysis_costs = defaultdict(dict)
  mca_costs = defaultdict(dict)

  # Write out candidate IR
  ir = "\n".join(
        [
          f"define {dsttype} @costfuzz({argsignature}) {{",
          pre,
          'tail call void asm sideeffect "# LLVM-MCA-BEGIN foo", "~{dirflag},~{fpsr},~{flags},~{rsp}"()',
          op,
          'tail call void asm sideeffect "# LLVM-MCA-END foo", "~{dirflag},~{fpsr},~{flags},~{rsp}"()',
          post,
          f"ret {dsttype} %result",
          "}",
          declaration,
        ]
      )

  with concurrent.futures.ThreadPoolExecutor(max_workers=args.num_threads) as e:
    analysis_results = defaultdict(dict)
    mca_results = {}

    for cpu in cpus:
      mca_results[cpu] = e.submit(_run_codegen, op, ir, cpu)
      for costkind in costkinds:
        analysis_results[costkind][cpu] = e.submit(_run_costmodel, op, opname, ir, cpu, costkind)

    for cpu in cpus:
      costs = mca_results[cpu].result()
      for costkind in costkinds:
        mca_costs[costkind][cpu] = costs[costkind]
        analysis_costs[costkind][cpu] = analysis_results[costkind][cpu].result()

  for costkind in costkinds:
    minanalysis = min(analysis_costs[costkind].values())
    maxanalysis = max(analysis_costs[costkind].values())
    minmca = min(mca_costs[costkind].values())
    maxmca = max(mca_costs[costkind].values())

    if maxmca != maxanalysis:
    #if abs(maxmca - maxanalysis) > 1:
      print(
        f"{dsttype} {opdesc} ({argsignature}): analysis cost ({minanalysis} - {maxanalysis}) vs mca cost ({minmca} - {maxmca}) ({costkind})"
      )
      for cpu in cpus:
        print(f"  {cpu} : {analysis_costs[costkind][cpu]} vs {mca_costs[costkind][cpu]}")
      if args.stop_on_diff:
        with open("fuzz.ll", "w") as f:
          f.write(ir)
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


# TODO - clean this up and ensure non-uniform constant really are non-uniform
def get_constant(elementcount, base, min, max, uniform = False):
  v = randint(min, max)
  if elementcount == 0:
    return f"{v}"
  elt = get_typeistub(0, base)
  cst = f"<"
  for x in range(elementcount):
    cst += f"{elt} {v}"
    if x != (elementcount - 1):
      cst += ", "
    if uniform is False:
      v = randint(min, max)
  cst += ">"
  return cst


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
              run_analysis(f"{srctype} %a0", dsttype, cmd, op, op, cpus)

          if srcbasewidth > dstbasewidth and op == "fptrunc":
            if srcbasewidth * elementcount <= maxwidth:
              run_analysis(f"{srctype} %a0", dsttype, cmd, op, op, cpus)


def fp_unaryops(maxwidth, ops, cpus):
  for op in ops:
    for basewidth in [32, 64]:
      for elementcount in [0, 2, 4, 8, 16]:
        if (basewidth * elementcount) <= maxwidth:
          type = get_type(elementcount, get_float_string(basewidth))
          cmd = f"%result = {op} {type} %a0"
          run_analysis(f"{type} %a0", type, cmd, op, op, cpus)


def fp_binops(maxwidth, ops, cpus):
  for op in ops:
    for basewidth in [32, 64]:
      for elementcount in [0, 2, 4, 8, 16]:
        if (basewidth * elementcount) <= maxwidth:
          type = get_type(elementcount, get_float_string(basewidth))
          cmd = f"%result = {op} {type} %a0, %a1"
          run_analysis(f"{type} %a0, {type} %a1", type, cmd, op, op, cpus)


# TODO - support bool predicate results for some targets
def fp_cmp(maxwidth, ops, cpus, boolresult = False):
  for op in ops:
    for basewidth in [32, 64]:
      for elementcount in [2, 4, 8, 16]:
        if (basewidth * elementcount) <= maxwidth:
          # TODO - add one / ueq handling
          #for cc in [ "oeq", "ogt", "oge", "olt", "ole", "one", "ord", "ueq", "ugt", "uge", "ult", "ule", "une", "uno" ]:
          for cc in [ "oeq", "ogt", "oge", "olt", "ole", "ord", "ugt", "uge", "ult", "ule", "une", "uno" ]:
            cctype = get_type(elementcount, f"i{1}")
            srctype = get_type(elementcount, get_float_string(basewidth))
            inttype = get_type(elementcount, f"i{basewidth}")
            dsttype = get_type(elementcount, f"i{basewidth}")
            cmd = "\n".join(
              [
                f"%cmp = {op} {cc} {srctype} %a0, %a1",
                f"%result = sext {cctype} %cmp to {dsttype}",
              ]
            )
            opname = f"{op} {cc}"
            run_analysis(f"{srctype} %a0, {srctype} %a1", dsttype, cmd, opname, opname, cpus)


def fp_unaryintrinsics(maxwidth, ops, cpus):
  for op in ops:
    for basewidth in [32, 64]:
      for elementcount in [0, 2, 4, 8, 16]:
        if (basewidth * elementcount) <= maxwidth:
          type = get_type(elementcount, get_float_string(basewidth))
          stub = get_typefstub(elementcount, basewidth)
          cmd = f"%result = call {type} @llvm.{op}.{stub}({type} %a0)"
          declaration = f"declare {type} @llvm.{op}.{stub}({type})"
          run_analysis(f"{type} %a0", type, cmd, op, op, cpus, declaration)

def fp_binaryintrinsics(maxwidth, ops, cpus):
  for op in ops:
    for basewidth in [32, 64]:
      for elementcount in [0, 2, 4, 8, 16]:
        if (basewidth * elementcount) <= maxwidth:
          type = get_type(elementcount, get_float_string(basewidth))
          stub = get_typefstub(elementcount, basewidth)
          cmd = f"%result = call {type} @llvm.{op}.{stub}({type} %a0, {type} %a1)"
          declaration = f"declare {type} @llvm.{op}.{stub}({type}, {type})"
          run_analysis(f"{type} %a0", type, cmd, op, op, cpus, declaration)

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
              run_analysis(f"{srctype} %a0", dsttype, cmd, op, op, cpus)

          if srcbasewidth > dstbasewidth and op == "trunc":
            if srcbasewidth * elementcount <= maxwidth:
              if elementcount != 0:
                run_analysis(f"{srctype} %a0", dsttype, cmd, op, op, cpus)


def int_binops(maxwidth, ops, cpus):
  for op in ops:
    for basewidth in [8, 16, 32, 64]:
      for elementcount in [0, 2, 4, 8, 16, 32, 64]:
        if (basewidth * elementcount) <= maxwidth:
          type = get_type(elementcount, f"i{basewidth}")
          cmd = f"%result = {op} {type} %a0, %a1"
          opname = f" {op} "
          run_analysis(f"{type} %a0, {type} %a1", type, cmd, opname, opname, cpus)


def int_shifts(maxwidth, ops, cpus):
  for op in ops:
    for basewidth in [8, 16, 32, 64]:
      #for elementcount in [0, 2, 4, 8, 16, 32, 64]:
      for elementcount in [2, 4, 8, 16, 32, 64]:
        if (basewidth * elementcount) <= maxwidth:
          type = get_type(elementcount, f"i{basewidth}")
          # general shift
          cmd = f"%result = {op} {type} %a0, %a1"
          run_analysis(f"{type} %a0, {type} %a1", type, cmd, op, op, cpus)
          if elementcount == 0:
            continue
          # constant shift
          cst = get_constant(elementcount, basewidth, 2, basewidth - 2, uniform = False)
          cstcmd = f"%result = {op} {type} %a0, {cst}"
          run_analysis(f"{type} %a0, {type} %a1", type, cmd, op, op + " (constant)", cpus)
          # uniform shift
          shuffletype = get_type(elementcount, "i32")
          pre = f"%splat = shufflevector {type} %a1, {type} poison, {shuffletype} zeroinitializer"
          cmd = f"%result = {op} {type} %a0, %splat"
          run_analysis(f"{type} %a0, {type} %a1", type, cmd, op, op + " (uniform)", cpus, pre = pre)
          # uniform constant shift
          cst = get_constant(elementcount, basewidth, 2, min(31, basewidth - 2), uniform = True)
          cstcmd = f"%result = {op} {type} %a0, {cst}"
          run_analysis(f"{type} %a0, {type} %a1", type, cstcmd, op, op + " (uniform constant)", cpus)


def int_cmp(maxwidth, ops, cpus, boolresult = False):
  for op in ops:
    for basewidth in [8, 16, 32, 64]:
      for elementcount in [2, 4, 8, 16, 32, 64]:
        if (basewidth * elementcount) <= maxwidth:
          for cc in [ "eq", "ne", "ugt", "uge", "ult", "ule", "sgt", "sge", "slt", "sle" ]:
            srctype = get_type(elementcount, f"i{basewidth}")
            cctype = get_type(elementcount, f"i{1}")
            dsttype = srctype
            cmd = "\n".join(
              [
                f"%cmp = {op} {cc} {srctype} %a0, %a1",
                f"%result = sext {cctype} %cmp to {dsttype}",
              ]
            )
            opname = f"{op} {cc}"
            run_analysis(f"{srctype} %a0, {srctype} %a1", dsttype, cmd, opname, opname, cpus)


def int_to_fp(maxwidth, ops, cpus):
  for op in ops:
    for srcbasewidth in [8, 16, 32, 64]:
      for dstbasewidth in [32, 64]:
        for elementcount in [0, 2, 4, 8, 16, 32, 64]:
          if (min(srcbasewidth, dstbasewidth) * elementcount) <= maxwidth:
            srctype = get_type(elementcount, f"i{srcbasewidth}")
            dsttype = get_type(elementcount, get_float_string(dstbasewidth))
            cmd = f"%result = {op} {srctype} %a0 to {dsttype}"
            run_analysis(f"{srctype} %a0", dsttype, cmd, op, op, cpus)


def fp_to_int(maxwidth, ops, cpus):
  for op in ops:
    for srcbasewidth in [32, 64]:
      for dstbasewidth in [8, 16, 32, 64]:
        for elementcount in [0, 2, 4, 8, 16, 32, 64]:
          if (min(srcbasewidth, dstbasewidth) * elementcount) <= maxwidth:
            srctype = get_type(elementcount, get_float_string(srcbasewidth))
            dsttype = get_type(elementcount, f"i{dstbasewidth}")
            cmd = f"%result = {op} {srctype} %a0 to {dsttype}"
            run_analysis(f"{srctype} %a0", dsttype, cmd, op, op, cpus)


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
            run_analysis(f"{type} %a0", type, cmd, op, f"{op} {boolval}", cpus, declaration)
          else:
            cmd = f"%result = call {type} @llvm.{op}.{stub}({type} %a0)"
            declaration = f"declare {type} @llvm.{op}.{stub}({type})"
            run_analysis(f"{type} %a0", type, cmd, op, op, cpus, declaration)


def int_binaryintrinsics(maxwidth, ops, cpus):
  for op in ops:
    for basewidth in [8, 16, 32, 64]:
      for elementcount in [0, 2, 4, 8, 16, 32, 64]:
        if (basewidth * elementcount) <= maxwidth:
          type = get_type(elementcount, f"i{basewidth}")
          stub = get_typeistub(elementcount, basewidth)
          cmd = f"%result = call {type} @llvm.{op}.{stub}({type} %a0, {type} %a1)"
          declaration = f"declare {type} @llvm.{op}.{stub}({type}, {type})"
          run_analysis(f"{type} %a0, {type} %a1", type, cmd, op, op, cpus, declaration)


def int_ternaryintrinsics(maxwidth, ops, cpus):
  for op in ops:
    for basewidth in [8, 16, 32, 64]:
      for elementcount in [0, 2, 4, 8, 16, 32, 64]:
        if (basewidth * elementcount) <= maxwidth:
          type = get_type(elementcount, f"i{basewidth}")
          stub = get_typeistub(elementcount, basewidth)
          cmd = f"%result = call {type} @llvm.{op}.{stub}({type} %a0, {type} %a1, {type} %a2)"
          declaration = f"declare {type} @llvm.{op}.{stub}({type}, {type}, {type})"
          run_analysis(f"{type} %a0, {type} %a1, {type} %a2", type, cmd, op, op, cpus, declaration)


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
          opname = f"vector.reduce.{op}"
          run_analysis(f"{vectype} %a0", scltype, cmd, opname, opname, cpus, declaration)


def filter_ops(targetops, ops):
  if len(targetops) == 0:
    return ops

  selectops = list()
  for targetop in targetops:
    if ops.count(targetop):
      selectops.append(targetop)
  return selectops


def test_cpus(targetops, maxwidth, cpulevel, cpus):
  ops = filter_ops(targetops, ["fpext", "fptrunc"])
  fp_cast(maxwidth, ops, cpus)

  ops = filter_ops(targetops, ["fneg"])
  fp_unaryops(maxwidth, ops, cpus)

  ops = filter_ops(targetops, ["fadd", "fsub", "fmul", "fdiv"])
  fp_binops(maxwidth, ops, cpus)

  ops = filter_ops(targetops, ["fcmp"])
  fp_cmp(maxwidth, ops, cpus, cpulevel == "avx512")

  ops = filter_ops(targetops, ["select"])
  # TODO - select with fcmp

  # TODO - fabs, fsqrt, ceil, floor, trunc, rint, nearbyint
  ops = filter_ops(targetops, ["sqrt"])
  fp_unaryintrinsics(maxwidth, ops, cpus)

  # TODO - copysign, maxnum, maxinum, minnum, mininum
  ops = filter_ops(targetops, ["maxnum", "minnum"])
  fp_binaryintrinsics(maxwidth, ops, cpus)

  # TODO - reduction op filtering
  # if len(targetops) == 0 or "reduce" in targetops:
  # fp_reductions(maxwidth, [ "fadd", "fmul", "fmax", "fmin" ], cpus)

  ops = filter_ops(targetops, ["sext", "zext", "trunc"])
  int_cast(maxwidth, ops, cpus)

  # TODO - sdiv/udiv/srem/urem (+ by constant/pow2 cases)
  ops = filter_ops(targetops, ["and", "or", "xor", "add", "sub", "mul"])
  int_binops(maxwidth, ops, cpus)

  ops = filter_ops(targetops, ["shl", "lshr", "ashr"])
  int_shifts(maxwidth, ops, cpus)

  ops = filter_ops(targetops, ["icmp"])
  int_cmp(maxwidth, ops, cpus, cpulevel == "avx512")

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

  ops = filter_ops(targetops, ["sadd.sat", "ssub.sat", "uadd.sat", "usub.sat"])
  int_binaryintrinsics(maxwidth, ops, cpus)

  # TODO - uniform / constant shift amount costs
  ops = filter_ops(targetops, ["fshl", "fshr"])
  int_ternaryintrinsics(maxwidth, ops, cpus)


def main():
  default_num_threads = os.cpu_count()

  # TODO - 2 modes - (a) create generic codegen for sse level and compare cpu analysis
  #          (b) create generic codegen for each cpu of a similar level and compare cpu analysis
  cpulevels = {
    "avx512"  : (512, ["x86-64-v4", "skylake-avx512", "icelake-server", "sapphirerapids", "znver4"]),
    "avx512f" : (512, ["knl", "x86-64-v4", "skylake-avx512", "icelake-server", "sapphirerapids", "znver4"]),
    "avx2"    : (256, ["x86-64-v3", "broadwell", "haswell", "skylake", "alderlake", "znver1", "znver2", "znver3", "x86-64-v4", "skylake-avx512", "icelake-server", "sapphirerapids", "znver4"]),
    "avx1"    : (256, ["btver2", "sandybridge", "x86-64-v3", "broadwell", "haswell", "skylake", "alderlake", "znver1", "znver2", "znver3", "x86-64-v4", "skylake-avx512", "icelake-server", "sapphirerapids", "znver4"]),
    "sse4.2"  : (128, ["x86-64-v2", "silvermont", "goldmont", "tremont", "nehalem", "btver2", "sandybridge", "x86-64-v3", "broadwell", "haswell", "skylake", "alderlake", "znver1", "znver2", "znver3", "x86-64-v4", "skylake-avx512", "icelake-server", "sapphirerapids", "znver4"]),
    "sse4.1"  : (128, ["penryn", "core2", "x86-64-v2", "silvermont", "goldmont", "tremont", "nehalem", "btver2", "sandybridge", "x86-64-v3", "broadwell", "haswell", "skylake", "alderlake", "znver1", "znver2", "znver3", "x86-64-v4", "skylake-avx512", "icelake-server", "sapphirerapids", "znver4"]),
    "ssse3"   : (128, ["atom", "penryn", "core2", "x86-64-v2", "silvermont", "goldmont", "tremont", "nehalem", "btver2", "sandybridge", "x86-64-v3", "broadwell", "haswell", "skylake", "alderlake", "znver1", "znver2", "znver3", "x86-64-v4", "skylake-avx512", "icelake-server", "sapphirerapids", "znver4"]),
    "sse3"    : (128, ["atom", "penryn", "core2", "x86-64-v2", "silvermont", "goldmont", "tremont", "nehalem", "btver2", "sandybridge", "x86-64-v3", "broadwell", "haswell", "skylake", "alderlake", "znver1", "znver2", "znver3", "x86-64-v4", "skylake-avx512", "icelake-server", "sapphirerapids", "znver4"]),
    "sse2"    : (128, ["x86-64", "atom", "penryn", "core2", "x86-64-v2", "silvermont", "goldmont", "tremont", "nehalem", "btver2", "sandybridge", "x86-64-v3", "broadwell", "haswell", "skylake", "alderlake", "znver1", "znver2", "znver3", "x86-64-v4", "skylake-avx512", "icelake-server", "sapphirerapids", "znver4"]),
    "xop"     : (256, ["bdver2"]),
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
    default=None,
    help="Only test cpus specific to a cpulevel(s)",
  )
  # TODO - --op(s) command line handling to select multiple ops for testing
  parser.add_argument(
    "--op", metavar="<op>", default=None, help="Only test requested op(s)"
  )
  parser.add_argument(
    "--stop-on-diff",
    action="store_true",
    help="Stop on first analysis/mca discrepancy, leaves fuzz.ll temp file",
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
  parser.add_argument(
    "-j",
    "--num-threads",
    type=int,
    default=default_num_threads,
    help=f"default:{default_num_threads}",
  )

  global args
  args = parser.parse_args()

  targetops = list()
  if args.op is not None:
    targetops = args.op.split(",")

  targetcpus = ["avx512", "avx2", "avx1", "sse4.2", "sse4.1", "ssse3", "sse2"]
  if args.cpulevel is not None:
    targetcpus = args.cpulevel.split(",")
    bad_levels = [l for l in args.cpulevel.split(",") if l not in cpulevels.keys()]
    if len(bad_levels) != 0:
      bad_level_msg = ",".join(bad_levels)
      raise Error(f"Unknown cpulevel : {bad_level_msg}")

  for targetcpu in targetcpus:
    (maxwidth, cpus) = cpulevels[targetcpu]
    test_cpus(targetops, maxwidth, targetcpu, cpus)

  return 0


if __name__ == "__main__":
  try:
    raise SystemExit(main())
  except Error as error:
    print(f"error: {error}")
    raise SystemExit(1) from error
