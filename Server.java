import java.io.*;
import java.net.*;
import java.security.*;
import javax.net.ssl.*;
import java.util.ArrayList;
import java.util.List;
import java.util.HashMap;
import java.util.Map;

public final class Server implements Runnable {

	private final int serverPort;
    private final boolean secure;
    private boolean keepalive = false;
    private boolean sslKeepalive = false;
    private Map<String, byte[]> resourceMap;
	private Map<String, String> redirectMap;
	private ServerSocket socket;
    private SSLServerSocket sslServersocket;
	private DataOutputStream toClientStream;
	private DataOutputStream ssltoClientStream;
    private BufferedReader fromClientStream;
	private BufferedReader sslfromClientStream;

    public Server(int serverPort, boolean secure) {
		this.serverPort = serverPort;
		this.secure = secure;
	}
        
    public void secure() throws Exception {  
	    boolean secure = true;
	    SSLContext sslContext;
	    String ksname = "ssl.jks";
	    sslContext = SSLContext.getInstance("TLS");
	    char[] password = "123456".toCharArray();
	    KeyStore ks = KeyStore.getInstance("JKS");
	    File file = new File(ksname);
	    FileInputStream fis = new FileInputStream(file);
	    System.out.println(fis);
	    ks.load(fis, password);
	    KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
	    kmf.init(ks, password);
	    TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
	    tmf.init(ks);
	    sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
	    SSLServerSocketFactory ssf = sslContext.getServerSocketFactory();
	    SSLServerSocket sslServersocket  = (SSLServerSocket) ssf.createServerSocket(serverPort);
	    System.out.println("SSL Server started: "+ sslServersocket);
	    System.out.println("Client authentication needed: "+ sslServersocket.getClass());
	    System.out.println("Enabled Protocols: "+ sslServersocket.getEnabledProtocols().toString());
	    while(true) {
			SSLSocket sslclientSocket = (SSLSocket) sslacceptFromClient(sslServersocket);
			if (sslclientSocket != null && sslclientSocket.isConnected()) {
			    try {
					this.handleRequest(secure);
			    } catch (IOException e) {
					System.out.println("IO exception handling request, continuing.");
			    }
			    
			    while(sslKeepalive) {
					try {
					    this.handleRequest(secure);
					} catch (IOException e) {
					    System.out.println("IO exception handling request, continuing.");
					}
				}
			    
			    try {
					sslclientSocket.close();
			    } catch (IOException e) {
					System.out.println("it's ok; the server already closed the connection.");
			    }
			}
	    }
	}
        
    public void nonsecure() throws IOException {    
	    boolean secure = false;
	    while(true) { 
	       Socket clientSocket = this.acceptFromClient();      
	       if (clientSocket != null && clientSocket.isConnected()) {
			   try {
			       this.handleRequest(secure);
			   } catch (IOException e) {
			       System.out.println("IO exception handling request, continuing.");
			   }
			   
			   while(keepalive) {
			       try {
				   		this.handleRequest(secure);
			       } catch (IOException e) {
				   		System.out.println("IO exception handling request, continuing.");
			       }
			   }
			   
			   try {
			       clientSocket.close();
			   } catch (IOException e) {
			       System.out.println("it's ok; the server already closed the connection.");
			   }
	       }
	    }
	}

    public void run() {  
	    try {
			this.loadResources();
	    } catch (IOException e) {
			System.out.println("Error communicating with client. aborting. Details: " + e);
	    }
	    
	    if (secure == true){
			System.out.println("This is a secure line");
	       	try {
		    	this.secure();
			} catch (Exception e) {
		    	System.out.println("exception creating secure sockets.");
			}
	    } else {
			try {
		    	this.bind();
		    	this.nonsecure();
			} catch (Exception e) {
		    	System.out.println("exception creating non-secure sockets.");
			}
		
	    }
	}
	
	public void loadResources() throws IOException {
		resourceMap = ResourceMap.loadFiles();
		redirectMap = ResourceMap.loadRedirects();
	}

	/**
	 * Creates a socket + binds to the desired server-side port #.
	 *
	 * throws IOException if the port is already in use.
	 */
	public void bind() throws IOException {
		socket = new ServerSocket(serverPort);
		System.out.println("Server bound and listening to port " + serverPort);
	}

	/**
	 * Waits for a client to connect, and then sets up stream objects for communication
 	 * in both directions.
	 *
	 * return the newly-created client socket if the connection is successfully
	 *     established, or null otherwise.
	 * throws IOException if the server fails to accept the connection.
	 */
    public Socket acceptFromClient() throws IOException {
		Socket clientSocket;
		try {
			clientSocket = socket.accept();
		} catch (SecurityException e) {
			System.out.println("The security manager intervened; your config is very wrong. " + e);
			return null;
		} catch (IllegalArgumentException e) {
			System.out.println("Probably an invalid port number. " + e);
			return null;
		} catch (IOException e) {
			System.out.println("IOException in socket.accept()");
			return null;
		}
		try {
			toClientStream = new DataOutputStream(clientSocket.getOutputStream());
			fromClientStream = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
		} catch (IOException e) {
			System.out.println("exception creating the stream objects.");
		}
		return clientSocket;
	}
    
	public SSLSocket sslacceptFromClient(SSLServerSocket sslServerSocket1) throws IOException {  
	    SSLSocket sslclientSocket1;
		try {
		    sslclientSocket1 = (SSLSocket) sslServerSocket1.accept();
		} catch (SecurityException e) {
			System.out.println("The security manager intervened; your config is very wrong. " + e);
			return null;
		} catch (IllegalArgumentException e) {
			System.out.println("Probably an invalid port number. " + e);
			return null;
		} catch (IOException e) {
			System.out.println("IOException in socket.accept()");
			return null;
		}
		try {
			toClientStream = new DataOutputStream(sslclientSocket1.getOutputStream());
			fromClientStream = new BufferedReader(new InputStreamReader(sslclientSocket1.getInputStream()));
		} catch (IOException e) {
			System.out.println("exception creating the stream objects.");
		}
		return sslclientSocket1;
	}

    public void handleRequest(boolean secure) throws IOException {
		List<String> rawRequest = new ArrayList<String>();
		String inputLine;
	    do {
			inputLine = fromClientStream.readLine();
			rawRequest.add(inputLine);
		} while ((inputLine != null) && (inputLine.length() > 0));
		if (inputLine != null) {
		    System.out.println(String.format("[%s]", rawRequest));	
		    HTTPRequest request = new HTTPRequest(rawRequest);	
		    System.out.println("isKeepAlive(): " + request.isKeepAlive());
		    if (secure){
				this.sslKeepalive = request.isKeepAlive();
		    } else if (!secure) {
				this.keepalive = request.isKeepAlive();
		    }
		    if (request.getType() != HTTPRequest.Command.GET && 
				request.getType() != HTTPRequest.Command.HEAD) {
				send403(request, String.format("%s not supported.", request.getType()));
				return;
		    } 
		    if (redirectMap.containsKey(request.getPath())) {
				send301(request, redirectMap.get(request.getPath()));
		    } else if (!resourceMap.containsKey(request.getPath())) {
				send404(request);
		    } else {
				byte[] content = resourceMap.get(request.getPath());
				send200(request, content);	
		    }
		}
    }

	private void send301(HTTPRequest request, String newUrl) throws IOException {
		String responseBody = new StringBuilder()
			.append("<HTML><HEAD><TITLE>301 Moved</TITLE></HEAD>\r\n")
    		.append("<BODY><H1>These aren't the droids you're looking for.</H1>\r\n")
    		.append(String.format("This resource has moved <A HREF=\"%s\">here</A>.\r\n", newUrl))
    		.append("</BODY></HTML>\r\n")
			.toString();
		StringBuilder response = new StringBuilder()
		    .append("HTTP/1.1 301 Moved Permanently\r\n")
		    .append(String.format("Location: %s\r\n", newUrl))
		    .append(String.format("Content-Type: text/html; charset=UTF-8\r\n"))
		    .append("Connection: close\r\n")
		    .append(String.format("Content-Length: %d\r\n", responseBody.length()));
		if (request.getType() == HTTPRequest.Command.GET) {
			response.append(String.format("\r\n%s", responseBody));
		}
		toClientStream.writeBytes(response.toString());
	}

	private void send404(HTTPRequest request) throws IOException {	
		String responseBody = new StringBuilder()
			.append("<HTML><HEAD><TITLE>404 Not Found</TITLE></HEAD>\r\n")
			.append("<BODY><H1>I can't find any resource of the name \r\n")
			.append(String.format("[%s] on this server.\r\n", request.getPath()))
			.append("</BODY></HTML>\r\n")
			.toString();
		StringBuilder response = new StringBuilder()
			.append("HTTP/1.1 404 Not Found\r\n")
			.append("Content-Type: text/html; charset=UTF-8\r\n")
			.append("Connection: close\r\n")
			.append(String.format("Content-Length: %d\r\n", responseBody.length()));
		if (request.getType() == HTTPRequest.Command.GET) {
			response.append(String.format("\r\n%s\r\n", responseBody));
		}
		try {
			toClientStream.writeBytes(response.toString());	
		} catch (IOException e) {
			System.out.println("Client closed the socket before we finished the whole message.");
		}
	}

	private void send403(HTTPRequest request, String errorDetail) throws IOException {
		StringBuilder response = new StringBuilder()
			.append("HTTP/1.1 403 Forbidden\r\n")
			.append("Connection: close\r\n")
			.append(String.format("Context-Length: %d\r\n", errorDetail.length()));
		if (request.getType() == HTTPRequest.Command.GET) {
			response.append(String.format("\r\n%s\r\n", errorDetail));
		}
		toClientStream.writeBytes(response.toString());	
	}

	private void send200(HTTPRequest request, byte[] content) throws IOException {
		StringBuilder response = new StringBuilder()
			.append("HTTP/1.1 200 OK\r\n")
			.append("Content-Type: text/html; charset=utf-8\r\n")
			.append("Server: project1\r\n")
			.append("Connection: close\r\n")
			.append(String.format("Content-Length: %d\r\n", content.length));
		StringBuilder responseKeepalive = new StringBuilder()
			.append("HTTP/1.1 200 OK\r\n")
		    .append("Date: Wed, 26 Dec 2007 19:00:00 GMT\r\n")
			.append("Content-Type: text/html; charset=utf-8\r\n")
			.append("Server: project1\r\n")
			.append("Connection: Keep-Alive\r\n")
			.append(String.format("Content-Length: %d\r\n", content.length));
		if (!request.isKeepAlive()) {
		    //This line is needed for head requests
		    System.out.println("about to send a response to close" + response.toString());
		    toClientStream.writeBytes(response.toString());
		    if (request.getType() == HTTPRequest.Command.GET) {
				toClientStream.writeBytes("\r\n");
				ByteArrayOutputStream outByteStream = new ByteArrayOutputStream();
				outByteStream.write(content, 0, content.length);
				outByteStream.writeTo(toClientStream);
		    }
		} else if (request.isKeepAlive()) {
		    System.out.println("About to send a response to keepAlive" + responseKeepalive.toString());
		    toClientStream.writeBytes(responseKeepalive.toString());
		    if (request.getType() == HTTPRequest.Command.GET) {
				toClientStream.writeBytes("\r\n");
				ByteArrayOutputStream outByteStream = new ByteArrayOutputStream();
				outByteStream.write(content, 0, content.length);
				outByteStream.writeTo(toClientStream);
		    }    
		}
	}

	public static void main(String argv[]) {
		Map<String, String> flags = Utils.parseCmdlineFlags(argv);
		boolean sslsecure = true;
		boolean nonssl = false;
		if (!flags.containsKey("--serverPort")) {
			System.out.println("usage: Server --serverPort=4040 --sslServerPort=6060");
			System.exit(-1);
		}
		int serverPort = -1;
		try {
			serverPort = Integer.parseInt(flags.get("--serverPort"));
		} catch (NumberFormatException e) {
			System.out.println("Invalid port number! Must be an integer.");
			System.exit(-1);
		}
		if (!flags.containsKey("--sslServerPort")) {
			System.out.println("usage: Server --serverPort=4040 --sslServerPort=6060");
			System.exit(-1);
		}
		int sslServerPort = -1;
		try {
			sslServerPort = Integer.parseInt(flags.get("--sslServerPort"));
		} catch (NumberFormatException e) {
			System.out.println("Invalid port number! Must be an integer.");
			System.exit(-1);
		}	
		Server httpserver = new Server(serverPort,nonssl);
		Thread serverthread = new Thread(httpserver, "http thread");
		serverthread.start();		
		Server sslServer = new Server(sslServerPort,sslsecure);
		Thread sslServerThread = new Thread(sslServer,"https thread");
		sslServerThread.start();
	}
}

