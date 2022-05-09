import banana.builtin.ModuleBuiltin;
import java.util.Arrays;
import java.util.List;

public class ModuleTest {
   private ModuleTest() {
   }

   public static void main(String[] args) {
      List testList = Arrays.asList("Hello,", "World!", "Banana");
      ModuleBuiltin.println(testList);
   }
}
