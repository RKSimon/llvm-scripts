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
    "alderlake"      : ["ADL-P", "alderlake", ("ADLPPort00", "ADLPPort01", "ADLPPort02", "ADLPPort03", "ADLPPort04", "ADLPPort05", "ADLPPort06", "ADLPPort07", "ADLPPort08", "ADLPPort09", "ADLPPort10", "ADLPPort11")],
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
      if instrNode.attrib['extension'] not in ['MMX', 'SSE', 'SSE2', 'SSE3', 'SSSE3', 'SSE4a', 'SSE4', 'AVX', 'AVX2', 'PCLMULQDQ', 'VPCLMULQDQ', 'FMA']:
         continue
      if any(x in instrNode.attrib['isa-set'] for x in ['FP16']):
         continue

      asm = instrNode.attrib['asm']
      sig = ''
      args = ''

      # Ignore uops.info custom instruction variants
      if asm.find("PCMPESTRIQ") != -1 or asm.find("PCMPISTRIQ") != -1 or asm.find("PCMPESTRMQ") != -1 or asm.find("PCMPISTRMQ") != -1:
        continue

      # TODO: Broken instructions (don't follow the standard naming convention)
      if asm.find("EXTRACT") != -1:
        continue
      if asm.find("INSERT") != -1 and instrNode.attrib['extension'] not in ['SSE4a']:
        continue
      if asm.find("RCPS") != -1 or asm.find("SQRTS") != -1 or asm.find("ROUNDS") != -1:
        continue
      if asm.find("PEXTR") != -1 or asm.find("PINSR") != -1 or asm.find("PREFETCH") != -1:
        continue
      if asm.find("BROADCAST") != -1 or asm.find("F128") != -1 or asm.find("I128") != -1 or asm.find("LDDQU") != -1 or asm.find("MXCSR") != -1:
        continue
      if asm.find("CRC") != -1:
        continue
      if asm.find("CVT") != -1:
        continue
      if asm.find("MOV") != -1:
        if asm.find("SX") == -1 and asm.find("ZX") == -1 and asm.find("DUP") == -1:
          continue

      archs = instrNode.iter('architecture')
      if not any(x.attrib['name'] == cpuname for x in archs):
        continue;

      ismmx = instrNode.attrib['category'] in ['MMX'] or instrNode.attrib['extension'] in ['MMX']
      issse = instrNode.attrib['extension'] in ['SSE', 'SSE2', 'SSE3', 'SSSE3', 'SSE4', 'SSE4a']
      issse4a = instrNode.attrib['extension'] in ['SSE4a']
      isfma = instrNode.attrib['extension'] in ['FMA']
      isopmask = instrNode.attrib.get('mask', '0') == '1'
      iszeroing = instrNode.attrib.get('zeroing', '0') == '1'

      isload = asm.startswith("{load}")
      asm = asm.removeprefix("{load}").lstrip()

      isstore = asm.startswith("{store}")
      asm = asm.removeprefix("{store}").lstrip()

      if asm.find("MOV") != -1:
        if asm.find("PMOVSX") != -1 or asm.find("PMOVZX") != -1 or asm.find("DUP") != -1:
          sig += 'r'

      # Cleanup signature to match LLVM opnames
      if asm.find("ABS") != -1 or asm.find("HMINPOS") != -1:
        sig += 'r'

      first = True
      fail = False
      for operandNode in instrNode.iter('operand'):
        operandIdx = int(operandNode.attrib['idx'])

        if operandNode.attrib.get('suppressed', '0') == '1':
          continue;

        if operandNode.attrib['type'] == 'reg':
          registers = operandNode.text.split(',')
          register = registers[min(operandIdx, len(registers)-1)]
          args += register + ' '
          if first and (ismmx or issse):
            args += register + ' '
        elif operandNode.attrib['type'] == 'mem':
          args += 'RDI i_0x1 %noreg '
        elif operandNode.attrib['type'] == 'imm':
          args += 'i_0x1 '

        if operandNode.attrib.get('r', '0') == '0':
          continue;

        if first:
          if asm.find("POPCNT") != -1:
            sig += operandNode.attrib.get('width', '')
            sig += 'r'
          elif operandNode.attrib.get('width', '128') == '256':
            asm += 'Y'

        if operandNode.attrib['type'] == 'reg':
          sig += 'r'
        elif operandNode.attrib['type'] == 'imm':
          sig += 'i'
        elif operandNode.attrib['type'] == 'mem':
          sig += 'm'
        else:
          fail = True
          continue;

        first = False

      if fail:
         continue;

      if ismmx:
         asm = "MMX_" + asm

      if issse4a:
        asm += 'I' if sig.find('i') != -1  else ''
        sig = ''

      if isfma:
        sig = 'm' if sig.find('m') != -1 else 'r'

      # SSE BLENDV xmm0 hack
      if asm.startswith("BLENDV") or asm.startswith("PBLENDV"):
         sig += '0'

      portlist = None
      uops = None
      for archNode in instrNode.iter('architecture'):
         if archNode.attrib['name'] != cpuname:
            continue;

         for measureNode in archNode.iter('measurement'):
            uops = float(measureNode.attrib['uops'])
            if measureNode.attrib.get('ports', None) is not None:
               portlist = measureNode.attrib['ports']

      if portlist is None or uops is None:
         fail = True;

      if fail:
         continue;

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
      print(f"    - '{asm}{sig} {args}'")
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
      print(f"info:            instruction is serial, repeating a random one.")
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
