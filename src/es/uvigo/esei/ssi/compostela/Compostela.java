package es.uvigo.esei.ssi.compostela;

import java.security.PublicKey;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Vector;

public class Compostela {

	public static void main(String[] args) {
		Map<String,byte[]> compostela = new LinkedHashMap<>();
		
		Pilgrim pilgrim = new Pilgrim("adrian", "fernandez", "44478888Q", "22/10/2014", "Camelias", "religion", "Peregrino.publica", "Peregrino.privada");
		Hostel hostel1 = new Hostel("1", "23/10/1014", "valenzana", "n/a", "Albergue1.publica", "Albergue1.privada");
		Hostel hostel2 = new Hostel("2", "24/10/1014", "lagunas", "n/a", "Albergue2.publica", "Albergue2.privada");
		Office oficina = new Office("Oficina.publica", "Oficina.privada");
		Vector<String> idAlbergue = new Vector<String>();
		idAlbergue.add("1");
		idAlbergue.add("2"); 
		Map<String,PublicKey> publicKeys = new LinkedHashMap<String,PublicKey>(); 
		publicKeys.put("1", hostel1.getPublicKey());
		publicKeys.put("2", hostel2.getPublicKey());
		compostela = pilgrim.generateCompostela(pilgrim.getPublicKey(), compostela);
		compostela = hostel1.stampCompostela(compostela, oficina.getPublicKey());
		compostela = hostel2.stampCompostela(compostela, oficina.getPublicKey());
		oficina.desempaquetarCompostela(compostela, idAlbergue, pilgrim.getPublicKey(), publicKeys);
	}

}
