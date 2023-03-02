import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

public class GeneradorClaves {

    /**
     * Método que genera un par de claves y las devuelve.
     */
    public static KeyPair generadorClaves(){
        try{
            KeyPair claves = null;
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            claves = kpg.generateKeyPair();
            return claves;
        } catch (NoSuchAlgorithmException e) {
            System.out.println("No existe ese algoritmo");
            throw new RuntimeException(e);
        }

    }


}
