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
            "def var a = null;\n" +
            "if (a) {\n" +
                "println(a);\n" +
            "} else {\n" +
                "println(\"twas null\");\n" +
            "}\n",
            compileOptions
        );
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
