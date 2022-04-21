package io.github.bananalang.compile;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import io.github.bananalang.parse.Parser;
import io.github.bananalang.parse.Tokenizer;
import io.github.bananalang.parse.ast.AccessExpression;
import io.github.bananalang.parse.ast.CallExpression;
import io.github.bananalang.parse.ast.ExpressionNode;
import io.github.bananalang.parse.ast.ExpressionStatement;
import io.github.bananalang.parse.ast.IdentifierExpression;
import io.github.bananalang.parse.ast.StatementList;
import io.github.bananalang.parse.ast.StatementNode;
import io.github.bananalang.parse.ast.StringExpression;
import io.github.bananalang.parse.ast.VariableDeclarationStatement;
import io.github.bananalang.parse.ast.VariableDeclarationStatement.VariableDeclaration;
import io.github.bananalang.parse.token.Token;
import io.github.bananalang.typecheck.Typechecker;
import javassist.ClassPool;
import javassist.CtMethod;
import javassist.LoaderClassPath;
import javassist.Modifier;
import javassist.bytecode.Descriptor;

public final class BananaCompiler {
    private final Typechecker types;
    private final StatementList root;
    private final CompileOptions options;
    private ClassWriter result;

    private final Deque<Map.Entry<StatementList, Integer>> scopes = new ArrayDeque<>();
    private final Map<String, Integer> variableDeclarations = new HashMap<>();
    private int currentVariableDecl = 1;

    private BananaCompiler(Typechecker types, StatementList root, CompileOptions options) {
        this.types = types;
        this.root = root;
        this.options = options;
        this.result = null;
    }

    public static ClassWriter compileFile(File file, CompileOptions options) throws IOException {
        try (FileReader reader = new FileReader(file)) {
            return compile(reader, options);
        }
    }

    public static ClassWriter compileFile(String fileName, CompileOptions options) throws IOException {
        try (FileReader reader = new FileReader(fileName)) {
            return compile(reader, options);
        }
    }

    public static ClassWriter compile(Reader inputReader, CompileOptions options) throws IOException {
        return compile(new Parser(inputReader), options);
    }

    public static ClassWriter compile(String source, CompileOptions options) throws IOException {
        return compile(new Parser(source), options);
    }

    public static ClassWriter compile(Tokenizer tokenizer, CompileOptions options) throws IOException {
        return compile(new Parser(tokenizer), options);
    }

    public static ClassWriter compile(List<Token> tokens, CompileOptions options) throws IOException {
        return compile(new Parser(tokens), options);
    }

    public static ClassWriter compile(Parser parser, CompileOptions options) throws IOException {
        StatementList root = parser.parse();
        ClassPool cp = new ClassPool(ClassPool.getDefault());
        cp.appendClassPath(new LoaderClassPath(BananaCompiler.class.getClassLoader()));
        Typechecker typechecker = new Typechecker(cp);
        typechecker.typecheck(root);
        return compile(typechecker, root, options);
    }

    public static ClassWriter compile(Typechecker types, StatementList ast, CompileOptions options) {
        BananaCompiler compiler = new BananaCompiler(types, ast, options);
        return compiler.compile();
    }

    private ClassWriter compile() {
        if (result == null) {
            result = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
            result.visit(52, Opcodes.ACC_PUBLIC, options.className(), null, "java/lang/Object", null);
            {
                MethodVisitor initMethod = result.visitMethod(Opcodes.ACC_PRIVATE, "<init>", "()V", null, null);
                initMethod.visitCode();
                initMethod.visitVarInsn(Opcodes.ALOAD, 0);
                initMethod.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
                initMethod.visitInsn(Opcodes.RETURN);
                initMethod.visitMaxs(-1, -1);
                initMethod.visitEnd();
            }
            if (needsMainMethod()) {
                MethodVisitor mainMethod = result.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "main", "([Ljava/lang/String;)V", null, null);
                mainMethod.visitParameter("args", 0);
                mainMethod.visitCode();
                compileStatementList(mainMethod, root, true);
                mainMethod.visitInsn(Opcodes.RETURN);
                mainMethod.visitMaxs(-1, -1);
                mainMethod.visitEnd();
            }
            result.visitEnd();
        }
        return result;
    }

    private boolean needsMainMethod() {
        return true;
    }

    private void compileStatementList(MethodVisitor method, StatementList node, boolean skipMethods) {
        scopes.addLast(new SimpleImmutableEntry<>(node, currentVariableDecl));
        for (StatementNode child : node.children) {
            if (child instanceof ExpressionStatement) {
                compileExpressionStatement(method, (ExpressionStatement)child);
            } else if (child instanceof VariableDeclarationStatement) {
                compileVariableDeclarationStatement(method, (VariableDeclarationStatement)child);
            } else {
                throw new IllegalArgumentException(node.getClass().getSimpleName() + " not supported for compilation yet");
            }
        }
        currentVariableDecl = scopes.removeLast().getValue();
    }

    private void compileExpressionStatement(MethodVisitor method, ExpressionStatement expr) {
        compileExpression(method, expr.expression);
        if (!types.getType(expr.expression).getName().equals("void")) {
            method.visitInsn(Opcodes.POP);
        }
    }

    private void compileVariableDeclarationStatement(MethodVisitor method, VariableDeclarationStatement stmt) {
        // Map<String, EvaluatedType> scopeTypes = types.getScopes().get(scopes.peekLast().getKey());
        for (VariableDeclaration decl : stmt.declarations) {
            if (decl.value != null) {
                // CtClass type = scopeTypes.get(decl.name).getJavassist();
                compileExpression(method, decl.value);
                variableDeclarations.put(decl.name, currentVariableDecl);
                method.visitVarInsn(Opcodes.ASTORE, currentVariableDecl);
                currentVariableDecl++;
            }
        }
    }

    private void compileExpression(MethodVisitor method, ExpressionNode expr) {
        if (expr instanceof StringExpression) {
            method.visitLdcInsn(((StringExpression)expr).value);
        } else if (expr instanceof CallExpression) {
            CallExpression callExpr = (CallExpression)expr;
            CtMethod methodToCall = types.getMethodCall(callExpr);
            boolean isStatic = Modifier.isStatic(methodToCall.getModifiers());
            if (callExpr.target instanceof AccessExpression && !isStatic) {
                compileExpression(method, ((AccessExpression)callExpr.target).target);
            }
            for (ExpressionNode arg : callExpr.args) {
                compileExpression(method, arg);
            }
            int opcode = isStatic
                ? Opcodes.INVOKESTATIC
                : (methodToCall.getDeclaringClass().isInterface()
                    ? Opcodes.INVOKEINTERFACE
                    : Opcodes.INVOKEVIRTUAL);
            method.visitMethodInsn(
                opcode,
                Descriptor.toJvmName(methodToCall.getDeclaringClass()),
                methodToCall.getName(),
                methodToCall.getMethodInfo().getDescriptor(),
                opcode == Opcodes.INVOKEINTERFACE
            );
        } else if (expr instanceof IdentifierExpression) {
            IdentifierExpression identExpr = (IdentifierExpression)expr;
            method.visitVarInsn(Opcodes.ALOAD, variableDeclarations.get(identExpr.identifier));
        } else {
            throw new IllegalArgumentException(expr.getClass().getSimpleName() + " not supported for compilation yet");
        }
    }
}
