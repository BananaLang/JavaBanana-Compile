package io.github.bananalang;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.util.function.Function;
import java.util.function.Supplier;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.util.CheckClassAdapter;

import banana.internal.annotation.NonNull;
import io.github.bananalang.compile.BananaCompiler;
import io.github.bananalang.compile.CompileOptions;
import io.github.bananalang.compilecommon.problems.GenericCompilationFailureException;
import io.github.bananalang.compilecommon.problems.ProblemCollector;

public class CompilerTest {
    public static final Supplier<String> TEST_SUPPLIER = () -> "Hello";
    @NonNull
    public static final Function<String, String> REVERSER = s -> null;

    public static void main(String[] args) throws IOException {
        CompileOptions compileOptions = new CompileOptions()
            .sourceFileName("test.ba")
            .defaultModuleName()
            .defaultClassName();
        ProblemCollector problemCollector = new ProblemCollector();
        ClassWriter result;
        try {
            result = BananaCompiler.compile(
                "println(10);\n" +
                "println(30);\n" +
                "println(130);\n" +
                "println(3221225472);\n" +
                "println(3221225472);\n" +
                "println(147573952589676412928);\n",
                compileOptions, problemCollector
            );
        } catch (GenericCompilationFailureException e) {
            System.out.println();
            System.out.println(e.getProblemCollector().ansiFormattedString());
            return;
        }
        System.out.println();
        System.out.println(problemCollector.ansiFormattedString());
        byte[] classData = result.toByteArray();

        PrintWriter pw = new PrintWriter(System.out);
        CheckClassAdapter.verify(new ClassReader(classData), true, pw);

        try (OutputStream out = new FileOutputStream(compileOptions.classFileName())) {
            out.write(classData);
        }

        System.out.println();
        try {
            new BinaryClassLoader()
                .loadFromBytecode(compileOptions.className(), classData)
                .getDeclaredMethod("main", String[].class)
                .invoke(null, new Object[] {args});
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static final class BinaryClassLoader extends ClassLoader {
        public Class<?> loadFromBytecode(String name, byte[] bytecode) {
            return super.defineClass(name, bytecode, 0, bytecode.length);
        }
    }
}
