package SSI_Compostela;

import java.io.*;

import java.security.*;
import java.security.spec.*;

import javax.crypto.*;
import javax.crypto.interfaces.*;
import javax.crypto.spec.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

// Necesario para usar el provider Bouncy Castle (BC)
//    Para compilar incluir el fichero JAR en el classpath

public class GenerarClaves {
	public static void main(String[] args) throws Exception {
		if (args.length != 1) {
			mensajeAyuda();
			System.exit(1);
		}

		
		// Anadir provider  (el provider por defecto no soporta RSA)
		Security.addProvider(new BouncyCastleProvider()); // Cargar el provider BC

		/*** Crear claves RSA 512 bits  */
		KeyPairGenerator generadorRSA = KeyPairGenerator.getInstance("RSA", "BC"); // Hace uso del provider BC
		generadorRSA.initialize(512);
		KeyPair clavesRSA = generadorRSA.generateKeyPair();
		PrivateKey clavePrivada = clavesRSA.getPrivate();
		PublicKey clavePublica = clavesRSA.getPublic();

		/*** 1 Volcar clave privada  a fichero */
		// 1.1 Codificar clave privada en formato PKS8 (necesario para escribirla a disco)
		PKCS8EncodedKeySpec pkcs8Spec = new PKCS8EncodedKeySpec(clavePrivada.getEncoded());

		// 1.2 Escribirla a fichero binario
		FileOutputStream out = new FileOutputStream(args[0] + ".privada");
		out.write(pkcs8Spec.getEncoded());
		out.close();

		/*** 3 Volcar clave publica  a fichero */
		// 3.1 Codificar clave publica en formato X509 (necesario para escribirla a disco)
		X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(clavePublica.getEncoded());

		// 3.2 Escribirla a fichero binario
		out = new FileOutputStream(args[0] + ".publica");
		out.write(x509Spec.getEncoded());
		out.close();
		
		System.out.println("Generadas claves RSA publica y privada de 512 bits en ficheros "+args[0] + ".publica"+ " y "+args[0] + ".privada");

	}

	public static void mensajeAyuda() {
		System.out.println("Generador de pares de clave RSA de 512 bits");
		System.out.println("\tSintaxis:   java GenerarClaves prefijo");
		System.out.println();
	}
}