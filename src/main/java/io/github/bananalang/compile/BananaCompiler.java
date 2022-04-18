package io.github.bananalang.compile;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.util.List;

import org.objectweb.asm.ClassWriter;

import io.github.bananalang.parse.Parser;
import io.github.bananalang.parse.Tokenizer;
import io.github.bananalang.parse.ast.ExpressionNode;
import io.github.bananalang.parse.ast.ExpressionStatement;
import io.github.bananalang.parse.ast.StatementList;
import io.github.bananalang.parse.ast.StatementNode;
import io.github.bananalang.parse.token.Token;

public final class BananaCompiler {
    private final StatementList root;
    private ClassWriter result;

    BananaCompiler(StatementList root) {
        this.root = root;
        this.result = null;
    }

    public static ClassWriter compileFile(File file) throws IOException {
        try (FileReader reader = new FileReader(file)) {
            return compile(reader);
        }
    }

    public static ClassWriter compileFile(String fileName) throws IOException {
        try (FileReader reader = new FileReader(fileName)) {
            return compile(reader);
        }
    }

    public static ClassWriter compile(Reader inputReader) throws IOException {
        return compile(new Parser(inputReader));
    }

    public static ClassWriter compile(String source) throws IOException {
        return compile(new Parser(source));
    }

    public static ClassWriter compile(Tokenizer tokenizer) throws IOException {
        return compile(new Parser(tokenizer));
    }

    public static ClassWriter compile(List<Token> tokens) throws IOException {
        return compile(new Parser(tokens));
    }

    public static ClassWriter compile(Parser parser) throws IOException {
        return compile(parser.parse());
    }

    public static ClassWriter compile(StatementList ast) {
        BananaCompiler compiler = new BananaCompiler(ast);
        return compiler.compile();
    }

    ClassWriter compile() {
        if (result == null) {
            result = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
            compileStatementList(root);
        }
        return result;
    }

    private void compileStatementList(StatementList node) {
        for (StatementNode child : node.children) {
            if (!(child instanceof ExpressionStatement)) {
                throw new UnsupportedOperationException("Non-expression statements not implemented");
            }
            compileExpressionStatement((ExpressionStatement)child);
        }
    }

    private void compileExpressionStatement(ExpressionStatement expr) {
        compileExpression(expr.expression);
    }

    private void compileExpression(ExpressionNode expr) {
    }
}
