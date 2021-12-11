package io.github.bananalang;

import java.io.IOException;

import io.github.bananalang.bytecode.ByteCodeFile;
import io.github.bananalang.compile.BananaCompiler;

public class CompilerTest {
    public static void main(String[] args) throws IOException {
        String source = "5 / 3 + 5 * 2;";
        ByteCodeFile bbc = BananaCompiler.compile(source);
        bbc.write("arithmetic.bbc");
        bbc.disassemble();
    }
}
