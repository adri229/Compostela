package es.uvigo.esei.ssi.compostela;

import java.security.PublicKey;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Vector;


/* 
 * Clase principal de la aplicacion que contiene el metodo main desde 
 * el cual comienza la ejecucion. Se crean instancias de los objetos 
 * Pilgrim, Hostel y Office. Se define el mapa de String y bytes Compostela
 * que contendra los datos cifrados del peregrino, su clave secreta y 
 * su firma. También contendra los datos cifrados de los albergues y sus 
 * correspondientes claves secretas y firmas. Se definen un vector que 
 * contiene IDs de los albergues y un mapa que contiene las claves publicas 
 * de los albergues respectivamente. En este metodo se llama a los metodos 
 * generate, stamp y unpack.
 * 
 * @author: Adrian Celix Fernandez
 * @author: Tamara Gonzalez Gomez 
 */

public class Compostela {

	public static void main(String[] args) {
		Map<String,byte[]> compostela = new LinkedHashMap<>();
		Pilgrim pilgrim = new Pilgrim("adrian", "fernandez", "44478888Q", "22/10/2014", "Camelias", "religion", "Peregrino.publica", "Peregrino.privada");
		Hostel hostel1 = new Hostel("1", "23/10/1014", "valenzana", "n/a", "Albergue1.publica", "Albergue1.privada");
		Hostel hostel2 = new Hostel("2", "24/10/1014", "lagunas", "n/a", "Albergue2.publica", "Albergue2.privada");
		Office office = new Office("Oficina.publica", "Oficina.privada");
		Vector<String> idHostel = new Vector<String>();
		idHostel.add("1");
		idHostel.add("2"); 
		Map<String,PublicKey> publicKeys = new LinkedHashMap<String,PublicKey>(); 
		publicKeys.put("1", hostel1.getPublicKey());
		publicKeys.put("2", hostel2.getPublicKey());
		compostela = pilgrim.generateCompostela(office.getPublicKey(), compostela);
		compostela = hostel1.stampCompostela(compostela, office.getPublicKey());
		compostela = hostel2.stampCompostela(compostela, office.getPublicKey());
		office.unpackCompostela(compostela, idHostel, pilgrim.getPublicKey(), publicKeys);
	}

}
