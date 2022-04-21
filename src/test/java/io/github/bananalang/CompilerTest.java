package io.github.bananalang;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.util.CheckClassAdapter;

import io.github.bananalang.compile.BananaCompiler;

public class CompilerTest {
    public static void main(String[] args) throws IOException {
        ClassWriter result = BananaCompiler.compile(
            "def var myVar = \"The Thing\";" +
            "println(myVar);"
        );
        byte[] classData = result.toByteArray();

        PrintWriter pw = new PrintWriter(System.out);
        CheckClassAdapter.verify(new ClassReader(classData), true, pw);

        try (OutputStream out = new FileOutputStream("GiveMeANameTODO.class")) {
            out.write(classData);
        }
    }
}
