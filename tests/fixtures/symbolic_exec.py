"""Use symbolic execution to find an input reaching a target address."""
import angr


def find_solution(binary_path, target_addr, avoid_addr):
    """Symbolically explore a binary to reach target_addr."""
    proj = angr.Project(binary_path, auto_load_libs=False)
    state = proj.factory.entry_state()
    simgr = proj.factory.simulation_manager(state)
    simgr.explore(find=target_addr, avoid=avoid_addr)
    if simgr.found:
        solution = simgr.found[0]
        return solution.posix.dumps(0)
    return None
