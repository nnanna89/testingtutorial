import java.math.BigInteger;
import java.security.MessageDigest;

public class NimcPasswordUtil {

    public static void main(String[] ar){
//        hashNIMCPassword();
        String address = "number 28 adebayo street off agboyi road alapere ketu lagos";
        String address2 = "30B anam 2 Street New Haven Enugu";
        String pattern = "^[A-Za-z0-9]+(\\s[A-Za-z0-9]+)+?";
        String pattern2 = "^[A-Za-z0-9]+(\\s[A-Za-z]+)+?";

        System.out.println(address.matches(pattern2));
    }

    public static void hashNIMCPassword(){
        try{

            BigInteger e = new
                    BigInteger("113621440243785421499955306133900099987164309503876199371900611085975699194905621710442876441889195302451922443555354266645737454327409509639333989384262385729949578624044207610948821627355876693570108394899808569346703874513552461157771585312437842555207875241788331401870311503661882350734256428011446552231");
            BigInteger m = new
                    BigInteger("99656440840574176563305385521896948249485597887868788305755844436736813735716889384156081404108856785411701458057572807701609821377138238971482595936817351313377639458003034637351529602924774615106031875065736828376549082962569871367654360928995574432638495308492887000005021125506027838956077501182295786099");
            String p = "Ebuka2019!";
            p=getPasswordHash(p);
            BigInteger pm = new BigInteger(p.getBytes());
            BigInteger b = pm.modPow(e, m);
            String pwd0 = new
                    sun.misc.BASE64Encoder().encode(b.toString().getBytes());
            System.out.println(pwd0);


        }
        catch(Exception r){
            r.printStackTrace();
        }
    }

    public static String getPasswordHash(String pwd) {

        try {
            MessageDigest m = MessageDigest.getInstance("sha-256");
            m.update(pwd.getBytes(), 0, pwd.length());

            return new BigInteger(1, m.digest()).toString(16);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}
