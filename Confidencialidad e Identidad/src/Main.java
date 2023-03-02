import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Base64;

public class Main {
    public static void main(String[] args) {
        File fichero = new File("src/fichero.txt");
        //Obtenemos las dos claves del emisor y del receptor
        KeyPair claveEmisor = GeneradorClaves.generadorClaves();
        KeyPair claveReceptor = GeneradorClaves.generadorClaves();
        //Llamamos a los metodos para cifrar y descifrar
        cifrarFichero(fichero,claveEmisor,claveReceptor);
        descifrarFichero(claveEmisor,claveReceptor);


    }

    /**
     * Método que cifrará el contenido de un fichero y lo almacenará en otro distinto
     * @param fichero Fichero a leer
     * @param emisor Par de claves del emisor
     * @param receptor Par de claves del receptor
     */
    private static void cifrarFichero(File fichero, KeyPair emisor, KeyPair receptor){

        try{


            BufferedReader br = new BufferedReader(new FileReader(fichero));
            FileWriter fw = new FileWriter(new File("src/ficheroCifrado.txt"));

            Cipher cipherEmisor = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            Cipher cipherReceptor = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            //Obtenemos la clave privada del emisor
            PrivateKey privadaEmisor = emisor.getPrivate();
            //Obtenemos la clave publica del receptor
            PublicKey publicaReceptor = receptor.getPublic();

            //Inicializamos los cipher
            cipherEmisor.init(Cipher.ENCRYPT_MODE,privadaEmisor);
            cipherReceptor.init(Cipher.ENCRYPT_MODE,publicaReceptor);

            //Leemos el fichero
            String textoFichero = "";
            String linea = br.readLine();
            while(linea != "" && linea != null){
                textoFichero += linea;
                linea = br.readLine();
            }

            byte[] textoACifrar = textoFichero.getBytes();

            //Ciframos con la clave privada del emisor
            byte[] mensajeCifrado1 = cipherEmisor.doFinal(textoACifrar);

            int blockSize = (((RSAPublicKey)publicaReceptor).getModulus().bitLength() +7) / 8 - 11;

            ByteArrayOutputStream bufferSalida = new ByteArrayOutputStream();

            //Ciframos con la clave publica del receptor
            int offset = 0;
            while (offset < mensajeCifrado1.length) {
                int tamanoBloqueActual = Math.min(blockSize, mensajeCifrado1.length - offset);
                byte[] mensajeCifrado2 = cipherReceptor.doFinal(mensajeCifrado1, offset, tamanoBloqueActual);

                bufferSalida.write(mensajeCifrado2);
                offset += tamanoBloqueActual;
            }

            byte[] cifrado = bufferSalida.toByteArray();
            bufferSalida.close();
            //Ciframos el mensaje en base64 y lo guardamos en el fichero
            String cifrado64 = Base64.getEncoder().encodeToString(cifrado);
            fw.write(cifrado64);
            br.close();
            fw.close();

        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        }


    }

    /**
     * Metodo que descifrará el contenido de un fichero
     * @param emisor Par de claves del emisor
     * @param receptor Par de claves del receptor
     */
    private static void descifrarFichero(KeyPair emisor, KeyPair receptor){
        try{

            //Obtenemos las claves
            PublicKey publicaEmisor = emisor.getPublic();
            PrivateKey privadaReceptor = receptor.getPrivate();
            FileReader fr = new FileReader(new File("src/ficheroCifrado.txt"));
            BufferedReader br = new BufferedReader(fr);
            //Leemos el texto cifrado
            String textoCifrado64 = br.readLine().trim();
            //Decodificamos el base64
            byte[] bytesCifrado = Base64.getDecoder().decode(textoCifrado64);
            Cipher cipherEmisor = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            Cipher cipherReceptor = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            //Inicializamos los cipher
            cipherEmisor.init(Cipher.DECRYPT_MODE,publicaEmisor);
            cipherReceptor.init(Cipher.DECRYPT_MODE,privadaReceptor);


            int blockSize = (((RSAPublicKey)publicaEmisor).getModulus().bitLength() + 7) / 8;

            ByteArrayOutputStream bufferSalida = new ByteArrayOutputStream();

            //Desencriptamos con la clave del receptor
            int offset = 0;
            while (offset < bytesCifrado.length) {
                int tamanoBloqueActual = Math.min(blockSize, bytesCifrado.length - offset);
                byte[] bloqueCifrado = Arrays.copyOfRange(bytesCifrado, offset, offset + tamanoBloqueActual);
                byte[] archivoDescifrado = cipherReceptor.doFinal(bloqueCifrado);

                bufferSalida.write(archivoDescifrado);
                offset += tamanoBloqueActual;
            }

            byte[] archivoDescrifrado1 = bufferSalida.toByteArray();

            ByteArrayOutputStream bufferSalida2 = new ByteArrayOutputStream();


            //Desencriptamos con la clave del emisor
            offset = 0;
            while (offset < archivoDescrifrado1.length) {
                int tamanoBloqueActual = Math.min(blockSize, archivoDescrifrado1.length - offset);
                byte[] bloqueCifrado = Arrays.copyOfRange(archivoDescrifrado1, offset, offset + tamanoBloqueActual);
                byte[] mensajeDescrifrado = cipherEmisor.doFinal(bloqueCifrado);

                bufferSalida2.write(mensajeDescrifrado);
                offset += tamanoBloqueActual;
            }

            byte[] ficheroDescifrado = bufferSalida2.toByteArray();

            //Mostramos por pantalla el contenido desencriptado
            String mensaje = new String(ficheroDescifrado);
            System.out.println("Mensaje: " + mensaje);


        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }

    }

}