#!/usr/bin/env python3

import argparse
from ast import Continue
import xml.etree.ElementTree as ET

class Error(Exception):
  """Simple exception type for erroring without a traceback."""

def get_all_cpu_details():
  return {
    "bonnell"        : ["BNL", "bonnell", ("AtomPort0", "AtomPort1")],
    "sandybridge"    : ["SNB", "sandybridge", ("SBPort0", "SBPort1", "SBPort23", "SBPort23", "SBPort4", "SBPort5")],
    "ivybridge"      : ["IVB", "ivybridge", ("SBPort0", "SBPort1", "SBPort23", "SBPort23", "SBPort4", "SBPort5")],
    "haswell"        : ["HSW", "haswell", ("HWPort0", "HWPort1", "HWPort2", "HWPort3", "HWPort4", "HWPort5", "HWPort6", "HWPort7")],
    "broadwell"      : ["BDW", "broadwell", ("BWPort0", "BWPort1", "BWPort2", "BWPort3", "BWPort4", "BWPort5", "BWPort6", "BWPort7")],
    "skylake"        : ["SKL", "skylake", ("SKLPort0", "SKLPort1", "SKLPort2", "SKLPort3", "SKLPort4", "SKLPort5", "SKLPort6", "SKLPort7")],
    "skylake-avx512" : ["SKX", "skylake-avx512", ("SKXPort0", "SKXPort1", "SKXPort2", "SKXPort3", "SKXPort4", "SKXPort5", "SKXPort6", "SKXPort7")],
    "cannonlake"     : ["CNL", "cannonlake", ("SKXPort0", "SKXPort1", "SKXPort2", "SKXPort3", "SKXPort4", "SKXPort5", "SKXPort6", "SKXPort7")],
    "cascadelake"    : ["CLX", "cascadelake", ("SKXPort0", "SKXPort1", "SKXPort2", "SKXPort3", "SKXPort4", "SKXPort5", "SKXPort6", "SKXPort7")],
    "icelake-server" : ["ICL", "icelake-server", ("ICXPort0", "ICXPort1", "ICXPort2", "ICXPort3", "ICXPort4", "ICXPort5", "ICXPort6", "ICXPort7", "ICXPort8", "ICXPort9")],
    "rocketlake"     : ["RKL", "rocketlake", ("ICXPort0", "ICXPort1", "ICXPort2", "ICXPort3", "ICXPort4", "ICXPort5", "ICXPort6", "ICXPort7", "ICXPort8", "ICXPort9")],
    "tigerlake"      : ["TGL", "tigerlake", ("ICXPort0", "ICXPort1", "ICXPort2", "ICXPort3", "ICXPort4", "ICXPort5", "ICXPort6", "ICXPort7", "ICXPort8", "ICXPort9")],
    "alderlake"      : ["ADL-P", "alderlake", ("ADLPPort00", "ADLPPort01", "ADLPPort02", "ADLPPort03", "ADLPPort04", "ADLPPort05", "ADLPPort06", "ADLPPort07", "ADLPPort08", "ADLPPort09", "ADLPPort11", "ADLPPort10")],
    "znver1"         : ["ZEN+", "znver1", ("ZnFPU0", "ZnFPU1", "ZnFPU2", "ZnFPU3")],
    "znver2"         : ["ZEN2", "znver2", ("Zn2FPU0", "Zn2FPU1", "Zn2FPU2", "Zn2FPU3")],
    "znver3"         : ["ZEN3", "znver3", ("Zn3FP0", "Zn3FP1", "Zn3FP2", "Zn3FP3", "Zn3FP45", "Zn3FP45")],
    "znver4"         : ["ZEN4", "znver4", ("Zn4FP0", "Zn4FP1", "Zn4FP2", "Zn4FP3", "Zn4FP45", "Zn4FP45")]
    }

def get_cpu_details(cpu):
  return get_all_cpu_details().get(cpu)

def distribute_pressure(pressure, ports, group):
  if len(group) == 1:
    ports[int(group)] += pressure
    return

  while pressure > 0.0:
    # collect current pressure value of all ports in op group
    pressure_map = dict()
    for p in list(group):
      i = int(p, 16)
      pressure_map[i] = ports[i]

    # if all the same pressure, then just distribute equally
    pressure_values = set(pressure_map.values())
    if len(pressure_values) == 1:
      for p in list(group):
        ports[int(p, 16)] += (pressure / float(len(group)))
      return

    # find the minimum pressure and which
    pressure_values = sorted(pressure_values)
    min_pressure = pressure_values[0]
    next_pressure = pressure_values[1]
    distrib_pressure = next_pressure - min_pressure

    min_pressure_ports = list()
    for p in list(group):
      if ports[int(p, 16)] == min_pressure:
        min_pressure_ports.append(p)

    if pressure <= distrib_pressure:
      for p in min_pressure_ports:
        ports[int(p, 16)] += (pressure / float(len(min_pressure_ports)))
      return

    for p in min_pressure_ports:
      ports[int(p, 16)] = next_pressure
      pressure -= next_pressure

def print_cpu_uops_yaml(cpu):
   root = ET.parse('instructions.xml')

   [cpuname, cpumodel, portmap] = get_cpu_details(cpu)

   for instrNode in root.iter('instruction'):
      if instrNode.attrib['extension'] not in ['BASE', 'ADOX_ADCX', 'BMI1', 'BMI2', 'LZCNT', 'MMX', 'SSE', 'SSE2', 'SSE3', 'SSSE3', 'SSE4a', 'SSE4', 'AVX', 'AVX2', 'AVX512VEX', 'AVX512EVEX', 'PCLMULQDQ', 'VPCLMULQDQ', 'F16C', 'FMA']:
         continue
      if any(x in instrNode.attrib['isa-set'] for x in ['FP16']):
         continue

      isaset = instrNode.attrib.get('isa-set', '')
      iclass = instrNode.attrib['iclass']
      iform = instrNode.attrib['iform']
      asm = instrNode.attrib['asm']
      size = ''
      sig = ''
      args = ''

      # Ignore uops.info custom instruction variants
      if asm.find('PCMPESTRIQ') != -1 or asm.find('PCMPISTRIQ') != -1 or asm.find('PCMPESTRMQ') != -1 or asm.find('PCMPISTRMQ') != -1:
        continue

      # TODO: Broken instructions (don't follow the standard naming convention)
      if asm.startswith(tuple(['LOCK','CMOV','ENTER','CMPXCHG','INVLPG','POP','PUSH','RET','SET','SLDT','STR','VER'])):
        continue
      if instrNode.attrib['extension'] in ['AVX512EVEX']:
        if any(x in asm for x in ['GATHER','SCATTER','VEXTRACT','VFIXUPIMM','VGETEXP','VGETMANT','VINSERT','VPMOVB2','VPMOV','VRANGE','VREDUCE','VRND','VSCALE','VP2INTERSECT','VPDP','VPSHUFBIT','BF16']):
          continue
      archs = instrNode.iter('architecture')
      if not any(x.attrib['name'] == cpuname for x in archs):
        continue

      ismov = asm.find('MOV') != -1
      ismaskmov = asm.find('MASKMOV') != -1
      iscrc32 = asm.find('CRC32') != -1
      isprefetch = instrNode.attrib['category'] in ['PREFETCH']
      isconvert = instrNode.attrib['category'] in ['CONVERT']
      isextract = asm.find('PEXTR') != -1 or asm.find('EXTRACT') != -1
      isconflict = instrNode.attrib['category'] in ['CONFLICT']
      iscompress = instrNode.attrib['category'] in ['COMPRESS']
      isexpand = instrNode.attrib['category'] in ['EXPAND']
      isbase = instrNode.attrib['extension'] in ['BASE']
      isadx = instrNode.attrib['extension'] in ['ADOX_ADCX']
      isbmi = instrNode.attrib['extension'] in ['BMI1','BMI2']
      islzcnt = instrNode.attrib['extension'] in ['LZCNT']
      ismmx = instrNode.attrib['category'] in ['MMX'] or instrNode.attrib['extension'] in ['MMX']
      issse = instrNode.attrib['extension'] in ['SSE', 'SSE2', 'SSE3', 'SSSE3', 'SSE4', 'SSE4a']
      issse4a = instrNode.attrib['extension'] in ['SSE4a']
      isf16c = instrNode.attrib['extension'] in ['F16C']
      isfma = instrNode.attrib['extension'] in ['FMA']
      isevex = instrNode.attrib.get('evex', '0') == '1'
      iskmask = instrNode.attrib['category'] in ['KMASK']
      ismask = instrNode.attrib.get('mask', '0') == '1'
      iszeroing = instrNode.attrib.get('zeroing', '0') == '1'
      isavx512scalar = isaset in ['AVX512F_SCALAR', 'AVX512DQ_SCALAR']
      isshiftrotate = isbase and instrNode.attrib['category'] in ['ROTATE','SHIFT']

      isload = asm.startswith('{load}')
      asm = asm.removeprefix('{load}').lstrip()

      isstore = asm.startswith('{store}')
      asm = asm.removeprefix('{store}').lstrip()

      # TODO: handle evex variants
      isevex_variant = asm.startswith('{evex}')
      asm = asm.removeprefix('{evex}').lstrip()
      if isevex_variant:
        continue

      fail = False
      opwidth = None
      srcwidth = None
      dstwidth = None
      operandCount = len(list(instrNode.iter('operand')))
      for operandNode in instrNode.iter('operand'):
        operandIdx = int(operandNode.attrib['idx'])
        first = operandIdx == 1
        last = operandIdx == operandCount

        if operandNode.attrib.get('suppressed', '0') == '1':
          continue

        isreg = operandNode.attrib['type'] == 'reg'
        ismem = operandNode.attrib['type'] == 'mem'
        isimm = operandNode.attrib['type'] == 'imm'
        isflags = operandNode.attrib['type'] == 'flags'
        isopmask = operandNode.attrib.get('opmask', '0') == '1'
        opwidth = operandNode.attrib.get('width', None)
        mem_suffix = operandNode.attrib.get('memory-suffix', None)
        xtype = operandNode.attrib.get('xtype')

        broadcast_factor = 1
        if mem_suffix is not None:
          broadcast_factor = int(mem_suffix.removeprefix('{1to').removesuffix('}'))

        r_sig = 'r'
        if isreg:
          registers = operandNode.text.split(',')
          register = registers[min(operandIdx, len(registers)-1)]
          args += register + ' '
          if first and (ismmx or issse or isbase or isadx):
            args += register + ' '
          if operandNode.attrib.get('implicit', '0') == '1' and register == 'CL':
            r_sig = register
          if xtype == 'i1':
            r_sig = 'k' # TODO
          # TODO: Handle seg registers
          if 'GS' in registers:
            r_sig = 's'
            fail = True
        elif ismem:
          args += 'RDI i_0x1 %noreg '
        elif isimm:
          args += 'i_0x1 '

        if isbase or isadx:
          if size == '' and opwidth is not None:
            dstwidth = size = opwidth

        if ismov and not ismaskmov:
          if opwidth is not None:
            if first:
              dstwidth = int(opwidth)
              isstore = ismem
            if last:
              srcwidth = int(opwidth)
              isload = ismem

        if isconvert and xtype is not None:
          xtype = xtype.removeprefix('i').removeprefix('u').removeprefix('f')
          if operandIdx == 1:
            dstwidth = int(xtype)
          if operandIdx == (3 if ismask else 2):
            srcwidth = int(xtype)
            if srcwidth > dstwidth:
              if opwidth is not None:
                if isavx512scalar or opwidth == '512':
                  size = 'Z'
                elif opwidth == '256':
                  size = 'Z256' if isevex else 'Y'
                elif isevex and opwidth == '128':
                  size = 'Z128'

        if isevex and opwidth is not None and size == '':
          if asm.startswith('VCMP') or asm.startswith('VPCMP') or asm.startswith('VFPCLASS') or asm.startswith('VPTEST'):
            opsize = int(opwidth) * broadcast_factor
            if isavx512scalar or opsize == 512:
              size = 'Z'
            elif opsize == 256:
              size = 'Z256'
            elif opsize == 128:
              size = 'Z128'

        if first:
          if isbmi or islzcnt:
            dstwidth = size = operandNode.attrib.get('width', '')
            if not ismem:
              continue
          elif asm.startswith('POPCNT'):
            size = operandNode.attrib.get('width', '')
          elif operandNode.attrib.get('r', '0') == '0' or isevex:
            if operandNode.attrib.get('w', '1') == '1':
              if opwidth is not None:
                if isavx512scalar or opwidth == '512':
                  size = 'Z'
                elif opwidth == '256':
                  size = 'Z256' if isevex else 'Y'
                elif isevex and opwidth == '128':
                  size = 'Z128'
            # TODO: either cleanup this logic or simplify some LLVM instruction names to avoid this
            if not isevex or not (isconflict or iscompress or isexpand or asm.startswith('VPLZCNT') or asm.startswith('VPOPCNT')):
              if not isbase and not isextract and not isconvert and not asm.startswith('KMOV'):
                continue
              if isconvert and (asm.find('2SD') != -1 or asm.find('2SS') != -1):
                continue

        if isreg:
          if not isopmask:
            sig += r_sig
        elif isimm:
          sig += 'i'
          if isbase and (opwidth == '8' or int(dstwidth) > int(opwidth)):
            if asm == 'TEST' and opwidth == '8':
              sig = sig # TODO
            elif asm in ['SHLD','SHRD']:
              sig += opwidth # TODO
            elif not (isshiftrotate or asm in ['IN','OUT','MOV']):
              sig += opwidth
        elif ismem:
          sig += 'mb' if mem_suffix is not None else 'm'
        elif isflags:
          continue
        else:
          fail = True
          continue

        if iscrc32:
          sig += operandNode.attrib.get('width', '')

      if isbase and (size == '' or int(size) > 64):
        fail = True

      # TODO: uops is missing memory resource info on ZEN4
      if cpuname == 'ZEN4' and sig.find('m') != -1:
        fail = True

      if fail:
        continue

      # Cleanup signature to match LLVM opnames
      if isbase:
        if asm.startswith(tuple(['MOVSX','MOVZX'])):
          sig += opwidth
        elif sig.startswith('m') and asm in ['XADD','XCHG']:
          continue # TODO

      if isprefetch or asm.find('MXCSR') != -1:
        size = ''
        sig = ''

      if isbmi or islzcnt:
        if asm.startswith('BEXTR') or asm.startswith('BZHI') or asm.startswith('SARX') or asm.startswith('SHLX') or asm.startswith('SHRX'):
          sig = 'rm' if sig == 'mr' else sig
        elif asm.startswith('BLS') or asm.startswith('TZCNT') or islzcnt:
          sig = 'r' + sig

      if ismmx or (isconvert and (asm.find('PI2') != -1 or asm.find('2PI') != -1)):
         asm = 'MMX_' + asm

      if ismov and not iskmask:
        if asm.find('PMOVSX') != -1 or asm.find('PMOVZX') != -1 or asm.find('DUP') != -1 or asm.find('MOVMSK') != -1:
          sig = 'r' + sig
        elif asm.find('MASKMOVDQU') != -1 or asm.find('MMX_MASKMOVQ') != -1:
          size = '64'
          sig = ''
        elif ismaskmov:
          sig = 'mr' if sig == 'rr' else sig
        elif isstore:
          sig = 'mr'
        elif isload and not isbase:
          sig = 'rm' if sig.find('m') != -1 else 'rr'
        elif sig == 'r':
          sig = 'rr'

        # Handle weird LLVM GPR<->XMM instruction names
        movdict  = {
          'MOVD_XMMdq_GPR32'    : 'MOVDI2PDI',
          'MOVD_XMMdq_GPR32d'   : 'MOVDI2PDI',
          'MOVD_XMMdq_MEMd'     : 'MOVDI2PDI',
          'MOVD_GPR32_XMMd'     : 'MOVPDI2DI',
          'MOVD_GPR32d_XMMd'    : 'MOVPDI2DI',
          'MOVD_MEMd_XMMd'      : 'MOVPDI2DI',

          'MOVQ_XMMdq_GPR64'    : 'MOV64toPQI',
          'MOVQ_XMMdq_GPR64q'   : 'MOV64toPQI',
          'MOVQ_XMMdq_MEMq'     : 'MOV64toPQI',
          'MOVQ_GPR64_XMMq'     : 'MOVPQIto64',
          'MOVQ_GPR64q_XMMq'    : 'MOVPQIto64',
          'MOVD_MEMq_XMMq'      : 'MOVPQIto64',
          'MOVQ_XMMdq_XMMq_7E'  : 'MOVZPQILo2PQI',
          'MOVQ_XMMdq_MEMq_7E'  : 'MOVQI2PQI',
          'MOVQ_XMMdq_XMMq_0F7E': 'MOVZPQILo2PQI',
          'MOVQ_XMMdq_MEMq_0F7E': 'MOVQI2PQI',
          'MOVQ_XMMdq_XMMq_D6'  : 'MOVPQI2QI',
          'MOVQ_XMMdq_XMMq_0FD6': 'MOVPQI2QI',
          'MOVQ_MEMq_XMMq_0FD6' : 'MOVPQI2QI',
          'MOVQ_MEMq_XMMq_D6'   : 'MOVPQI2QI',

          'MOVD_MMXq_GPR32'     : 'MMX_MOVD64',
          'MOVD_GPR32_MMXd'     : 'MMX_MOVD64g',
          'MOVD_MMXq_MEMd'      : 'MMX_MOVD64',
          'MOVD_MEMd_MMXd'      : 'MMX_MOVD64',

          'MOVQ_MMXq_GPR64'     : 'MMX_MOVD64to64',
          'MOVQ_MMXq_MEMq'      : 'MMX_MOVD64to64',
          'MOVQ_GPR64_MMXq'     : 'MMX_MOVD64from64',
          'MOVQ_MEMq_MMXq'      : 'MMX_MOVD64from64',
          'MOVQ_MMXq_MEMq_0F6F' : 'MMX_MOVQ64',
          'MOVQ_MMXq_MMXq_0F6F' : 'MMX_MOVQ64',
          'MOVQ_MEMq_MMXq_0F7F' : 'MMX_MOVQ64',
          'MOVQ_MMXq_MMXq_0F7F' : 'MMX_MOVQ64',

          'MOVQ2DQ_XMMdq_MMXq'  : 'MMX_MOVQ2DQ',
          'MOVDQ2Q_MMXq_XMMq'   : 'MMX_MOVDQ2Q',
        }
        iform_prefix = 'V' if iform.startswith('V') else ''
        iform_strip = iform.removeprefix('V')
        if iform_strip in movdict:
          asm = iform_prefix + movdict[iform_strip]

      if asm.find('KNOT') != -1:
        sig = 'k' + sig

      if asm.find('LDDQU') != -1:
        sig = 'r' + sig

      if asm.find('ABS') != -1 or asm.find('HMINPOS') != -1:
        sig = 'r' + sig

      if asm.find('RCPS') != -1 or asm.find('SQRTS') != -1:
        sig = 'm' if sig.find('m') != -1 else 'r'

      if asm.find('ROUNDS') != -1:
        sig = 'mi' if sig.find('m') != -1 else 'ri'

      if isf16c or asm.find('PS2PH') != -1:
        sig = sig.replace('i', '')

      if asm.find('BROADCAST') != -1:
        sig = 'r' + sig

      if asm.find('F128') != -1 or asm.find('I128') != -1:
        size = ''

      # 3 arg signature cleanups
      if isfma or asm.find('VFMADD') != -1 or asm.find('VFNMADD') != -1 or asm.find('VFMSUB') != -1 or asm.find('VFNMSUB') != -1:
        sig = 'm' if sig.find('m') != -1 else 'r'

      if asm.find('VPMADD52') != -1 or asm.find('VPSHLDV') != -1 or asm.find('VPSHRDV') != -1:
        sig = 'm' if sig.find('m') != -1 else 'r'

      # Signature postfixes
      if issse4a:
        asm += 'I' if sig.find('i') != -1  else ''
        sig = ''

      # SSE BLENDV xmm0 hack
      if asm.startswith('BLENDV') or asm.startswith('PBLENDV'):
         sig += '0'

      if isevex and isavx512scalar and not ismov:
        if not (asm.startswith('VRCP14') or asm.startswith('VRSQRT14') or asm.startswith('VFPCLASS')):
          sig += '_Int'

      if isevex and ismask:
        sig += 'kz' if iszeroing else 'k'

      portlist = None
      uops = None
      for archNode in instrNode.iter('architecture'):
         if archNode.attrib['name'] != cpuname:
            continue

         for measureNode in archNode.iter('measurement'):
            uops = float(measureNode.attrib['uops'])
            # TODO: Prefer uops_retire_slots (fused domain) uop count
            #if measureNode.attrib.get('uops_retire_slots', None) is not None:
            #   uops = min(uops, float(measureNode.attrib['uops_retire_slots']))
            if measureNode.attrib.get('ports', None) is not None:
               portlist = measureNode.attrib['ports']

      if portlist is None or uops is None:
         fail = True

      if fail:
         continue

      # ports="1*p01+1*p23"
      ops = list()
      ports = dict()
      for x in portlist.split('+'):
        [count,group] = x.split('*')
        group = group.removeprefix('FP').removeprefix('p')
        ops.append((count,group))
        for p in list(group):
          ports[int(p, 16)] = 0.0

      # sort ops by #ports they can be applied to
      ops = sorted(ops, key=lambda e: len(e[1]))

      # distribute resource pressure
      for (count,group) in ops:
        pressure = float(count)
        distribute_pressure(pressure, ports, group)

      args = args.lstrip().rstrip()

      mapped_ports = dict.fromkeys(portmap, 0.0)
      for i, p in ports.items():
        portname = portmap[i]
        mapped_ports[portname] += p

      print(f"---")
      print(f"mode:            uops")
      print(f"key:")
      print(f"  instructions:")
      print(f"    - '{asm}{size}{sig} {args}'")
      print(f"  config:          ''")
      print(f"  register_initial_values:")
      print(f"    - 'XMM0=0x0'")
      print(f"    - 'MXCSR=0x0'")
      print(f"cpu_name:        {cpumodel}")
      print(f"llvm_triple:     x86_64-unknown-linux-gnu")
      print(f"num_repetitions: 10000")
      print(f"measurements:")
      for portname, portpressure in mapped_ports.items():
         print(f"  - {{ key: {portname}, value: {portpressure}, per_snippet_value: {portpressure} }}")
      print(f"  - {{ key: NumMicroOps, value: {uops}, per_snippet_value: {uops} }}")
      print(f"error:           ''")
      print(f"info:            '{iform}'")
      print(f"assembled_snippet: B0004883EC08C7042400000000C7442404000000009D37373737C3")
      print(f"...")

def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument(
    '-cpu', '-mcpu',
    default='haswell',
    choices=get_all_cpu_details().keys(),
    help='Target CPU (default=haswell)',
  )
  parser.add_argument(
    '-mode',
    default='uops',
    choices=['uops', 'inverse_throughput', 'latency'],
    help='Capture Mode (default=uops)',
  )
  args = parser.parse_args()

  if args.mode == 'uops':
    print_cpu_uops_yaml(args.cpu)

if __name__ == "__main__":
    main()
