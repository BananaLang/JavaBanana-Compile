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
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.commons.InstructionAdapter;

import io.github.bananalang.parse.Parser;
import io.github.bananalang.parse.Tokenizer;
import io.github.bananalang.parse.ast.AccessExpression;
import io.github.bananalang.parse.ast.BinaryExpression;
import io.github.bananalang.parse.ast.CallExpression;
import io.github.bananalang.parse.ast.ExpressionNode;
import io.github.bananalang.parse.ast.ExpressionStatement;
import io.github.bananalang.parse.ast.FunctionDefinitionStatement;
import io.github.bananalang.parse.ast.IdentifierExpression;
import io.github.bananalang.parse.ast.ImportStatement;
import io.github.bananalang.parse.ast.NullExpression;
import io.github.bananalang.parse.ast.ReturnStatement;
import io.github.bananalang.parse.ast.StatementList;
import io.github.bananalang.parse.ast.StatementNode;
import io.github.bananalang.parse.ast.StringExpression;
import io.github.bananalang.parse.ast.VariableDeclarationStatement;
import io.github.bananalang.parse.ast.VariableDeclarationStatement.VariableDeclaration;
import io.github.bananalang.parse.token.Token;
import io.github.bananalang.typecheck.EvaluatedType;
import io.github.bananalang.typecheck.MethodCall;
import io.github.bananalang.typecheck.ScriptMethod;
import io.github.bananalang.typecheck.Typechecker;
import javassist.ClassPool;
import javassist.CtMethod;
import javassist.LoaderClassPath;
import javassist.Modifier;
import javassist.bytecode.Descriptor;

public final class BananaCompiler {
    private static final String NULLABLE_ANNOTATION = "Lbanana/internal/annotation/Nullable;";
    private static final String NONNULL_ANNOTATION = "Lbanana/internal/annotation/NonNull;";

    private final Typechecker types;
    private final StatementList root;
    private final CompileOptions options;
    private ClassWriter result;

    private final Deque<Map.Entry<StatementList, Integer>> scopes = new ArrayDeque<>();
    private final Map<String, Integer> variableDeclarations = new HashMap<>();
    private int currentVariableDecl;

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
            for (StatementNode child : root.children) {
                if (child instanceof FunctionDefinitionStatement) {
                    FunctionDefinitionStatement functionDefinition = (FunctionDefinitionStatement)child;
                    ScriptMethod methodDefinition = types.getMethodDefinition(functionDefinition);
                    StringBuilder descriptor = new StringBuilder("(");
                    for (EvaluatedType arg : methodDefinition.getArgTypes()) {
                        descriptor.append(Descriptor.of(arg.getJavassist()));
                    }
                    descriptor.append(')').append(Descriptor.of(methodDefinition.getReturnType().getJavassist()));
                    MethodVisitor mv = result.visitMethod(
                        Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC,
                        functionDefinition.name,
                        descriptor.toString(),
                        null,
                        null
                    );
                    if (!methodDefinition.getReturnType().getName().equals("void")) {
                        mv.visitAnnotation(
                            methodDefinition.getReturnType().isNullable()
                                ? NULLABLE_ANNOTATION
                                : NONNULL_ANNOTATION,
                            false
                        );
                    }
                    currentVariableDecl = 0;
                    for (VariableDeclaration arg : functionDefinition.args) {
                        if (arg.value != null) {
                            throw new RuntimeException("Default parameters not supported yet");
                        }
                        EvaluatedType type = methodDefinition.getArgTypes()[currentVariableDecl];
                        mv.visitParameter(arg.name, 0);
                        mv.visitParameterAnnotation(
                            currentVariableDecl,
                            type.isNullable() ? NULLABLE_ANNOTATION : NONNULL_ANNOTATION,
                            false
                        );
                        variableDeclarations.put(arg.name, currentVariableDecl++);
                    }
                    mv.visitCode();
                    if (!compileStatementList(new InstructionAdapter(mv), functionDefinition.body, true, true)) {
                        if (methodDefinition.getReturnType().getName().equals("void")) {
                            mv.visitInsn(Opcodes.RETURN);
                        } else {
                            mv.visitInsn(Opcodes.ACONST_NULL);
                            mv.visitInsn(Opcodes.ARETURN);
                        }
                    }
                    mv.visitMaxs(-1, -1);
                    mv.visitEnd();
                    variableDeclarations.clear();
                }
            }
            if (needsMainMethod()) {
                MethodVisitor mainMethod = result.visitMethod(
                    Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                    "main",
                    "([Ljava/lang/String;)V",
                    null,
                    null
                );
                mainMethod.visitParameter("args", 0);
                mainMethod.visitCode();
                currentVariableDecl = 1;
                if (!compileStatementList(new InstructionAdapter(mainMethod), root, true, true)) {
                    mainMethod.visitInsn(Opcodes.RETURN);
                }
                mainMethod.visitMaxs(-1, -1);
                mainMethod.visitEnd();
                variableDeclarations.clear();
            }
            result.visitEnd();
        }
        return result;
    }

    private boolean needsMainMethod() {
        for (StatementNode child : root.children) {
            if (child instanceof ImportStatement) continue;
            if (child instanceof FunctionDefinitionStatement) continue;
            return true;
        }
        return false;
    }

    private boolean compileStatementList(InstructionAdapter method, StatementList node, boolean skipMethods, boolean isTopLevel) {
        scopes.addLast(new SimpleImmutableEntry<>(node, currentVariableDecl));
        for (int i = 0; i < node.children.size(); i++) {
            StatementNode child = node.children.get(i);
            if (child instanceof ExpressionStatement) {
                compileExpressionStatement(method, (ExpressionStatement)child);
            } else if (child instanceof VariableDeclarationStatement) {
                compileVariableDeclarationStatement(method, (VariableDeclarationStatement)child);
            } else if (child instanceof ReturnStatement) {
                compileReturnStatement(method, (ReturnStatement)child);
                currentVariableDecl = scopes.removeLast().getValue();
                if (i < node.children.size() - 1) {
                    throw new IllegalArgumentException("Unreachable code detected");
                }
                return true;
            } else if (!(child instanceof ImportStatement) && !(child instanceof FunctionDefinitionStatement)) {
                throw new IllegalArgumentException(child.getClass().getSimpleName() + " not supported for compilation yet");
            }
        }
        currentVariableDecl = scopes.removeLast().getValue();
        return false;
    }

    private void compileExpressionStatement(InstructionAdapter method, ExpressionStatement stmt) {
        compileExpression(method, stmt.expression);
        if (!types.getType(stmt.expression).getName().equals("void")) {
            method.pop();
        }
    }

    private void compileVariableDeclarationStatement(InstructionAdapter method, VariableDeclarationStatement stmt) {
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

    private void compileReturnStatement(InstructionAdapter method, ReturnStatement stmt) {
        if (stmt.value == null) {
            method.visitInsn(Opcodes.RETURN);
            return;
        }
        compileExpression(method, stmt.value);
        method.visitInsn(Opcodes.ARETURN);
    }

    private void compileExpression(InstructionAdapter method, ExpressionNode expr) {
        if (expr instanceof StringExpression) {
            method.aconst(((StringExpression)expr).value);
        } else if (expr instanceof NullExpression) {
            method.aconst(null);
        } else if (expr instanceof CallExpression) {
            CallExpression callExpr = (CallExpression)expr;
            MethodCall methodToCall = types.getMethodCall(callExpr);
            int opcode;
            String ownerName, descriptor;
            Label safeNavigationLabel = null;
            if (methodToCall.isScriptMethod()) {
                for (ExpressionNode arg : callExpr.args) {
                    compileExpression(method, arg);
                }
                ScriptMethod scriptMethod = methodToCall.getScriptMethod();
                opcode = Opcodes.INVOKESTATIC;
                ownerName = options.className();
                StringBuilder descriptorBuilder = new StringBuilder("(");
                for (EvaluatedType argType : scriptMethod.getArgTypes()) {
                    descriptorBuilder.append(Descriptor.of(argType.getJavassist()));
                }
                descriptor = descriptorBuilder.append(')')
                    .append(Descriptor.of(scriptMethod.getReturnType().getJavassist()))
                    .toString();
            } else {
                CtMethod javaMethod = methodToCall.getJavaMethod();
                boolean isStatic = Modifier.isStatic(javaMethod.getModifiers());
                if (callExpr.target instanceof AccessExpression && !isStatic) {
                    AccessExpression accessExpr = (AccessExpression)callExpr.target;
                    compileExpression(method, accessExpr.target);
                    if (accessExpr.safeNavigation) {
                        safeNavigationLabel = new Label();
                        method.dup();
                        method.ifnull(safeNavigationLabel);
                    }
                }
                descriptor = javaMethod.getMethodInfo().getDescriptor();
                if (Modifier.isVarArgs(javaMethod.getModifiers())) {
                    int actualArgCount = Descriptor.numOfParameters(descriptor);
                    for (int i = 0; i < actualArgCount - 1; i++) {
                        compileExpression(method, callExpr.args[i]);
                    }
                    method.iconst(callExpr.args.length - actualArgCount + 1);
                    int endParen = descriptor.indexOf(')');
                    String arrType = descriptor.substring(descriptor.lastIndexOf('L', endParen - 2) + 1, endParen - 1);
                    method.visitTypeInsn(Opcodes.ANEWARRAY, arrType);
                    for (int i = actualArgCount - 1; i < callExpr.args.length; i++) {
                        method.dup();
                        method.iconst(i - actualArgCount + 1);
                        compileExpression(method, callExpr.args[i]);
                        method.visitInsn(Opcodes.AASTORE);
                    }
                } else {
                    for (ExpressionNode arg : callExpr.args) {
                        compileExpression(method, arg);
                    }
                }
                opcode = isStatic
                    ? Opcodes.INVOKESTATIC
                    : (javaMethod.getDeclaringClass().isInterface()
                        ? Opcodes.INVOKEINTERFACE
                        : Opcodes.INVOKEVIRTUAL);
                ownerName = Descriptor.toJvmName(javaMethod.getDeclaringClass());
            }
            method.visitMethodInsn(
                opcode,
                ownerName,
                methodToCall.getName(),
                descriptor,
                opcode == Opcodes.INVOKEINTERFACE
            );
            if (safeNavigationLabel != null) {
                method.visitLabel(safeNavigationLabel);
            }
        } else if (expr instanceof IdentifierExpression) {
            IdentifierExpression identExpr = (IdentifierExpression)expr;
            method.visitVarInsn(Opcodes.ALOAD, variableDeclarations.get(identExpr.identifier));
        } else if (expr instanceof BinaryExpression) {
            BinaryExpression binExpr = (BinaryExpression)expr;
            switch (binExpr.type) {
                case NULL_COALESCE: {
                    compileExpression(method, binExpr.left);
                    Label endLabel = new Label();
                    method.dup();
                    method.ifnonnull(endLabel);
                    method.pop();
                    compileExpression(method, binExpr.right);
                    method.visitLabel(endLabel);
                    break;
                }
                default:
                    throw new AssertionError(binExpr.type);
            }
        } else {
            throw new IllegalArgumentException(expr.getClass().getSimpleName() + " not supported for compilation yet");
        }
    }
}
