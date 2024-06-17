LLVM Helper Scripts

* check_cost_tables.py

  Compares the TTI analysis cost values for IR instructions vs the llvm-mca values for various CPU targets and reports differences. Assumes that TTI numbers should represent the worst case of all CPUs.

* uops_to_exegesis.py

  Extracts data from uops.info instructions.xml and converts to a exegesis capture yaml file for a specific cpu.