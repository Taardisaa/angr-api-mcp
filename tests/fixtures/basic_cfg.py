"""Extract CFG and list all basic blocks in a binary."""
import angr


def analyze_cfg(binary_path):
    """Load a binary and compute its control flow graph."""
    proj = angr.Project(binary_path, auto_load_libs=False)
    cfg = proj.analyses.CFGFast()
    for node in cfg.graph.nodes():
        block = proj.factory.block(node.addr)
    return cfg
