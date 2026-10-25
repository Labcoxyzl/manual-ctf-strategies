// Export one authored function from the actual Ghidra decompiler.
// @category Validation
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

public class RecoverComparison extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2) throw new IllegalArgumentException("function-name output-path");
        Function target = null;
        for (Function function : currentProgram.getFunctionManager().getFunctions(true)) {
            if (function.getName().equals(args[0])) target = function;
        }
        if (target == null) throw new IllegalArgumentException("Function not found: " + args[0]);
        DecompInterface decompiler = new DecompInterface();
        try {
            if (!decompiler.openProgram(currentProgram)) throw new IllegalStateException(decompiler.getLastMessage());
            DecompileResults result = decompiler.decompileFunction(target, 30, monitor);
            if (!result.decompileCompleted()) throw new IllegalStateException(result.getErrorMessage());
            String code = result.getDecompiledFunction().getC();
            Files.writeString(Path.of(args[1]), code, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
            println("Recovered " + target.getName() + " at " + target.getEntryPoint());
        } finally {
            decompiler.dispose();
        }
    }
}
