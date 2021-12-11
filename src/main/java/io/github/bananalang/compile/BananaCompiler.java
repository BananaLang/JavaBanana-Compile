package io.github.bananalang.compile;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.math.BigInteger;
import java.util.List;

import io.github.bananalang.JavaBananaConstants;
import io.github.bananalang.bytecode.ByteCodeFile;
import io.github.bananalang.bytecode.ByteCodes;
import io.github.bananalang.bytecode.NoCollisionsConstantTable;
import io.github.bananalang.bytecode.constants.DoubleConstant;
import io.github.bananalang.bytecode.constants.IntegerConstant;
import io.github.bananalang.parse.Parser;
import io.github.bananalang.parse.Tokenizer;
import io.github.bananalang.parse.ast.AssignmentExpression;
import io.github.bananalang.parse.ast.BinaryExpression;
import io.github.bananalang.parse.ast.BooleanExpression;
import io.github.bananalang.parse.ast.CallExpression;
import io.github.bananalang.parse.ast.DecimalExpression;
import io.github.bananalang.parse.ast.ExpressionNode;
import io.github.bananalang.parse.ast.ExpressionStatement;
import io.github.bananalang.parse.ast.IdentifierExpression;
import io.github.bananalang.parse.ast.IntegerExpression;
import io.github.bananalang.parse.ast.StatementList;
import io.github.bananalang.parse.ast.StatementNode;
import io.github.bananalang.parse.ast.StringExpression;
import io.github.bananalang.parse.ast.UnaryExpression;
import io.github.bananalang.parse.token.Token;

public final class BananaCompiler {
    private static final BigInteger TWO = BigInteger.valueOf(2);
    private static final BigInteger MAX_SBYTE = BigInteger.valueOf(128);
    private static final BigInteger MIN_SBYTE = BigInteger.valueOf(-129);
    private static final BigInteger MAX_BYTE = BigInteger.valueOf(256);
    private static final BigInteger MIN_BYTE = BigInteger.valueOf(-1);

    private final StatementList root;
    private ByteCodeFile result;
    private NoCollisionsConstantTable constantTable;

    BananaCompiler(StatementList root) {
        this.root = root;
        this.result = null;
    }

    public static ByteCodeFile compileFile(File file) throws IOException {
        try (FileReader reader = new FileReader(file)) {
            return compile(reader);
        }
    }

    public static ByteCodeFile compileFile(String fileName) throws IOException {
        try (FileReader reader = new FileReader(fileName)) {
            return compile(reader);
        }
    }

    public static ByteCodeFile compile(Reader inputReader) throws IOException {
        return compile(new Parser(inputReader));
    }

    public static ByteCodeFile compile(String source) throws IOException {
        return compile(new Parser(source));
    }

    public static ByteCodeFile compile(Tokenizer tokenizer) throws IOException {
        return compile(new Parser(tokenizer));
    }

    public static ByteCodeFile compile(List<Token> tokens) throws IOException {
        return compile(new Parser(tokens));
    }

    public static ByteCodeFile compile(Parser parser) throws IOException {
        return compile(parser.parse());
    }

    public static ByteCodeFile compile(StatementList ast) {
        BananaCompiler compiler = new BananaCompiler(ast);
        return compiler.compile();
    }

    ByteCodeFile compile() {
        if (result == null) {
            result = new ByteCodeFile();
            constantTable = new NoCollisionsConstantTable();
            compileStatementList(root);
            result.getConstantTable().addAll(constantTable.getTable());
            constantTable = null;
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
        if (JavaBananaConstants.DEBUG) {
            result.putCode(ByteCodes.DEBUG_PRINT);
        }
        result.putCode(ByteCodes.POP);
    }

    private void compileExpression(ExpressionNode expr) {
        if (expr instanceof AssignmentExpression) {
            throw new UnsupportedOperationException("Assignment expressions not implemented");
        } else if (expr instanceof BinaryExpression) {
            BinaryExpression binExpr = (BinaryExpression)expr;
            compileExpression(binExpr.left);
            compileExpression(binExpr.right);
            switch (binExpr.type) {
                case ADD:
                    result.putCode(ByteCodes.ADD);
                    break;
                case SUBTRACT:
                    result.putCode(ByteCodes.SUB);
                    break;
                case MULTIPLY:
                    result.putCode(ByteCodes.MUL);
                    break;
                case DIVIDE:
                    result.putCode(ByteCodes.DIV);
                    break;
                default:
                    throw new UnsupportedOperationException("Binary operator " + binExpr.type + " not supported yet");
            }
        } else if (expr instanceof BooleanExpression) {
            throw new UnsupportedOperationException("Boolean expressions not implemented");
        } else if (expr instanceof CallExpression) {
            throw new UnsupportedOperationException("Call expressions not implemented");
        } else if (expr instanceof DecimalExpression) {
            DecimalExpression decExpr = (DecimalExpression)expr;
            int constIndex = constantTable.add(new DoubleConstant(decExpr.value));
            result.putLoadConstant(constIndex);
        } else if (expr instanceof IdentifierExpression) {
            throw new UnsupportedOperationException("Identifiers not implemented");
        } else if (expr instanceof IntegerExpression) {
            IntegerExpression intExpr = (IntegerExpression)expr;
            if (intExpr.value.equals(BigInteger.ZERO)) {
                result.putCode(ByteCodes.LOAD_0);
            } else if (intExpr.value.equals(BigInteger.ONE)) {
                result.putCode(ByteCodes.LOAD_1);
            } else if (intExpr.value.equals(TWO)) {
                result.putCode(ByteCodes.LOAD_2);
            } else if (intExpr.value.compareTo(MIN_SBYTE) > 0 && intExpr.value.compareTo(MAX_SBYTE) < 0) {
                result.putSByte(intExpr.value.byteValue());
            } else if (intExpr.value.compareTo(MIN_BYTE) > 0 && intExpr.value.compareTo(MAX_BYTE) < 0) {
                result.putByte((byte)(intExpr.value.intValue() & 0xff));
            } else {
                int constIndex = constantTable.add(new IntegerConstant(intExpr.value));
                result.putLoadConstant(constIndex);
            }
        } else if (expr instanceof StringExpression) {
            throw new UnsupportedOperationException("Strings not implemented");
        } else if (expr instanceof UnaryExpression) {
            throw new UnsupportedOperationException("Unary expressions not implemented");
        }
    }
}
