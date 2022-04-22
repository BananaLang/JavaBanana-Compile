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

public class CompilerTest {
    public static void main(String[] args) throws IOException {
        CompileOptions compileOptions = new CompileOptions()
            .sourceFileName("test.ba")
            .defaultModuleName()
            .defaultClassName();
        ClassWriter result = BananaCompiler.compile(
            "import java.lang.Class.forName;" +
            "println(forName(\"java.util.HashMap\").getDeclaredMethod(" +
                "\"computeIfAbsent\", forName(\"java.lang.Object\"), forName(\"java.util.function.Function\")" +
            "));",
            compileOptions
        );
        byte[] classData = result.toByteArray();

        PrintWriter pw = new PrintWriter(System.out);
        CheckClassAdapter.verify(new ClassReader(classData), true, pw);

        try (OutputStream out = new FileOutputStream(compileOptions.classFileName())) {
            out.write(classData);
        }
    }
}
