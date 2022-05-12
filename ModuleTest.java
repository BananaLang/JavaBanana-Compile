import banana.builtin.ModuleBuiltin;
import io.github.bananalang.CompilerTest;

public class ModuleTest {
   private ModuleTest() {
   }

   public static void main(String[] args) {
      String testVar = (String)CompilerTest.TEST_SUPPLIER.get();
      ModuleBuiltin.println(testVar);
      Object var10000 = CompilerTest.REVERSER.apply(testVar);
      if (var10000 == null) {
         throw $nullAssertionFailure("REVERSER(testVar)");
      } else {
         ModuleBuiltin.println((String)var10000);
      }
   }
}
