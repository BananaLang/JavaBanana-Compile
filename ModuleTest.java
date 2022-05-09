import banana.builtin.ModuleBuiltin;
import banana.builtin.StringExtensions;

public class ModuleTest {
   private ModuleTest() {
   }

   public static void main(String[] args) {
      ModuleBuiltin.println(StringExtensions.add("Hello ", "world!"));
   }
}
