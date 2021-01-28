package test.calculator.stepdef;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSEncryptionPart;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.CredentialException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.Merlin;
import org.apache.ws.security.message.WSSecHeader;
import org.apache.ws.security.message.WSSecSignature;
import org.apache.ws.security.message.WSSecTimestamp;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;


public class XMLSigner {

	 private static String ALIAS = "alias";
	    private static String PASSWORD = "test";
	    private static String KEY_FILE = "1571753451.p12";
	    private static final String KEY_FILE_TYPE = "PKCS12";
	    private static String OUTPUT_FILE_PATH = "sample.xml";

	    private static Crypto crypto;
	    private static final Properties cryptoProperties = new Properties();
	    private static final WSSecSignature signature = new WSSecSignature();
	    private static final WSSecTimestamp timestamp = new WSSecTimestamp();
	    private static final WSSecHeader header = new WSSecHeader();
	    private static Document signedDocument;

	    public static void main(String[] args) {
	        // ARGS: input_file_path, save_file_path, key_file_path
			/*
			 * OUTPUT_FILE_PATH = args[1]; // save file path KEY_FILE = args[2]; // key file
			 * path PASSWORD = args[3]; ALIAS = args[4];
			 */

	        String message = readFileFromArgs(args);
	        init();
	        signMessage(message);
	        saveToFile(getStringFromDoc());
	    }

	    private static String readFileFromArgs(String[] args) {
	        String message = null;
	        try {
	            message =  new String(Files.readAllBytes(Paths.get(args[0])));
	        } catch (IOException e) {
	            System.err.println("Cannot open file with SOAP message.");
	            System.exit(1);
	        } catch (IndexOutOfBoundsException e) {
	            System.err.println("Pass path to the file with SOAP message.");
	            System.exit(2);
	        }
	        return message;
	    }

	    private static void init() {
	        setCryptoProperties();

	        try {
	            crypto = new Merlin(cryptoProperties);
	        } catch (CredentialException | IOException e) {
	            System.err.println("Error during initializing Crypto instance.");
	            System.exit(3);
	        }
	    }

	    private static void setCryptoProperties(){
	        cryptoProperties.setProperty("org.apache.ws.security.crypto.merlin.keystore.alias", "alias");
	        cryptoProperties.setProperty("org.apache.ws.security.crypto.merlin.keystore.password", "test");
	        cryptoProperties.setProperty("org.apache.ws.security.crypto.merlin.keystore.type", "PKCS12");
	        cryptoProperties.setProperty("org.apache.ws.security.crypto.merlin.keystore.file", "1571753451.p12");
	    }

	    private static Document xmlToDoc(String xml) {
	        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
	        factory.setNamespaceAware(true);

	        try {
	            DocumentBuilder documentBuilder = factory.newDocumentBuilder();
	            InputSource source = new InputSource();
	            source.setCharacterStream(new StringReader(xml));
	            return documentBuilder.parse(source);
	        } catch (ParserConfigurationException | SAXException | IOException e) {
	            System.err.println("Error during converting file content to xml document.");
	            System.exit(4);
	        }

	        return null;
	    }

	    private static void signMessage(String message) {
	        Document document = xmlToDoc(message);
	        header.setMustUnderstand(true);
	        signature.setSignatureAlgorithm(WSConstants.C14N_EXCL_OMIT_COMMENTS);
	        signature.setSignatureAlgorithm(WSConstants.RSA);
	        signature.setUserInfo(ALIAS, PASSWORD);
	        signature.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);

	        List<WSEncryptionPart> parts = new ArrayList<>();
	        parts.add(new WSEncryptionPart(WSConstants.ELEM_BODY, WSConstants.URI_SOAP11_ENV, ""));
	        parts.add(new WSEncryptionPart("Action", "http://www.w3.org/2005/08/addressing", ""));
	        parts.add(new WSEncryptionPart("ReplyTo", "http://www.w3.org/2005/08/addressing", ""));
	        parts.add(new WSEncryptionPart("MessageID", "http://www.w3.org/2005/08/addressing", ""));
	        parts.add(new WSEncryptionPart("To", "http://www.w3.org/2005/08/addressing", ""));
	        parts.add(new WSEncryptionPart("Timestamp", WSConstants.WSU_NS, ""));
	        signature.setParts(parts);

	        try {
	            header.insertSecurityHeader(document);
	            timestamp.build(document, header);
	            signature.build(document, crypto, header);
	        } catch (WSSecurityException e) {
	            System.err.println("Error during signing document.");
	            System.exit(5);
	        }


	        signedDocument = document;
	    }

	    private static String getStringFromDoc() {
	        DOMSource domSource = new DOMSource(signedDocument);
	        StringWriter writer = new StringWriter();
	        StreamResult result = new StreamResult(writer);
	        TransformerFactory tf = TransformerFactory.newInstance();
	        try {
	            Transformer transformer = tf.newTransformer();
	            transformer.transform(domSource, result);
	        } catch (TransformerException e) {
	            System.err.println("Error during converting signed document to string.");
	            System.exit(6);
	        }
	        writer.flush();
	        return writer.toString();
	    }

	    private static void saveToFile(String content) {
	        try {
	            Files.write(Paths.get(".\\sample.xml"), content.getBytes());
	        } catch (IOException e) {
	            System.err.println("Error during saving signed document to file.");
	            System.exit(7);
	        }
	    }

}
