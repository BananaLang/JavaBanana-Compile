package io.github.bananalang;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.util.CheckClassAdapter;

import io.github.bananalang.compile.BananaCompiler;
import io.github.bananalang.compile.CompileOptions;
import io.github.bananalang.compilecommon.problems.GenericCompilationFailureException;
import io.github.bananalang.compilecommon.problems.ProblemCollector;

public class CompilerTest {
    public static void main(String[] args) throws IOException {
        CompileOptions compileOptions = new CompileOptions()
            .sourceFileName("test.ba")
            .defaultModuleName()
            .defaultClassName();
        ProblemCollector problemCollector = new ProblemCollector();
        ClassWriter result;
        try {
            result = BananaCompiler.compile(
                "def lazy var myVar = myExpensiveFunc();\n" +
                "println(\"created variable\");\n" +
                "def String myExpensiveFunc() {\n" +
                    "println(\"initialized\");\n" +
                    "return \"hello\";\n" +
                "}\n" +
                "println(myVar);\n",
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
