import banana.builtin.Int;
import banana.builtin.ModuleBuiltin;
import banana.internal.util.FastNumbers;
import java.math.BigInteger;

public class ModuleTest {
   // $FF: synthetic field
   private static Int $const0;
   // $FF: synthetic field
   private static Int $const1;
   // $FF: synthetic field
   private static Int $const2;

   private ModuleTest() {
   }

   public static void main(String[] args) {
      ModuleBuiltin.println(FastNumbers.$10);
      ModuleBuiltin.println(Int.$INTERNED[158]);
      Int var10000 = $const0;
      if ($const0 == null) {
         var10000 = $const0 = Int.valueOf(130);
      }

      ModuleBuiltin.println(var10000);
      var10000 = $const1;
      if ($const1 == null) {
         var10000 = $const1 = Int.valueOf(3221225472L);
      }

      ModuleBuiltin.println(var10000);
      var10000 = $const1;
      if ($const1 == null) {
         var10000 = $const1 = Int.valueOf(3221225472L);
      }

      ModuleBuiltin.println(var10000);
      var10000 = $const2;
      if ($const2 == null) {
         var10000 = $const2 = Int.valueOf(new BigInteger("147573952589676412928"));
      }

      ModuleBuiltin.println(var10000);
   }
}
