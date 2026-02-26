"""Inspect register values and memory from a simulation state."""
import angr


def inspect_state(binary_path, target_addr):
    """Reach target_addr and inspect the resulting register state."""
    proj = angr.Project(binary_path, auto_load_libs=False)
    state = proj.factory.entry_state()
    simgr = proj.factory.simulation_manager(state)
    simgr.explore(find=target_addr)
    if simgr.found:
        found_state = simgr.found[0]
        rax_val = found_state.solver.eval(found_state.regs.rax)
        return rax_val
    return None
