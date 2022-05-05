import banana.builtin.ModuleBuiltin;
import banana.builtin.StringExtensions;
import banana.internal.annotation.BananaModule;
import banana.internal.annotation.ExtensionMethod;
import banana.internal.annotation.NonNull;
import banana.internal.annotation.Nullable;

@BananaModule
public class ModuleTest {
   private ModuleTest() {
   }

   @ExtensionMethod
   public static void echo(@NonNull final String this) {
      ModuleBuiltin.println(this);
   }

   @ExtensionMethod
   private static void echo2(@NonNull final String this, @Nullable String other) {
      echo(StringExtensions.add(this, other));
   }

   public static void main(String[] args) {
      String hello = "Hello ";
      echo2(hello, "world!");
   }
}
