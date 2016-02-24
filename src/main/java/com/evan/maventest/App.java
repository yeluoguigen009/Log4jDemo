package com.evan.maventest;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.Serializable;
import java.lang.reflect.Field;
import java.net.Authenticator;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.PasswordAuthentication;
import java.net.Socket;
import java.net.URL;
import java.net.URLConnection;
import java.security.KeyStore;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Random;
import java.util.Scanner;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.json.JSONException;
import org.json.JSONObject;

import com.notnoop.apns.APNS;
import com.notnoop.apns.ApnsDelegate;
import com.notnoop.apns.ApnsNotification;
import com.notnoop.apns.ApnsService;
import com.notnoop.apns.DeliveryError;
import com.notnoop.exceptions.InvalidSSLConfig;

/**
 * Hello world!
 *
 */

class Father {
	void Print() {
		System.out.println("This is father");
	}
}

class Son extends Father {
	public int age = 5;

	void Print() {
		System.out.println("This is Son");
	}
}

class RoomStates{
	public static final int Draft = 0;
	public static final int Pending = 1;
	public static final int Broadcasting = 2;
	public static final int Disconnected = 3;
}

enum StreamStates{
	Pending,
	Start,
	End
}

class SerializableSon implements Serializable {
	public int age = 5;

	void Print() {
		System.out.println("This is Son");
	}
}

class CURD<T> {
	void create() {
		try {
			Class<?> model = Class.forName(this.getClass().getName());
			for (Field f : model.getFields()) {
				System.out.println(f.getName());
			}
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		}
		System.out.println("Create " + this.toString());
	}

	void query() {
		System.out.println("Query " + this.toString());
	}
}

class AD extends CURD<AD> {
	public String adName;
	private String test;
	public String adPrice;

	public String toString() {
		return "Advertisement";
	}

}

class SkillBook{
	public int bookId;
	public String bookName;
	public int price;
	
	public SkillBook(int bookId, String bookName, int price) {
		this.bookId = bookId;
		this.bookName = bookName;
		this.price = price;
	}
	
	public SkillBook(String bookName, int price) {
		this.bookName = bookName;
		this.price = price;
	}
}

class Pet{
	public String name;
	public Set<Integer> petSkills = new HashSet<Integer>();
	
	public Pet(String name, Set<Integer> petSkills){
		this.name = name;
		
		if (petSkills != null)
			this.petSkills = petSkills;
	}
}

class Master{
	public String name;
	public int money;
	
	public Master(String name, int money){
		this.name = name;
		this.money = money;
	}
}

public class App {
	
	static int maxId32 = 0;
	
	static Object tsLock = new Object();

	public static Socket TestConnection() {
		String certName = "test";
		String hostname = "feedback.push.apple.com";
		String certPath = "e:\\test.p12";
		String password = "Mozat!@#$%";
		int port = 2195;
		try {
			KeyStore ks = KeyStore.getInstance("PKCS12");

			System.out.println("[APN][" + certName + "], Connecting to apple gateway: " + hostname + ":" + port);
			SSLContext context = SSLContext.getInstance("TLS");
			KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
			FileInputStream fin = new FileInputStream(new File(certPath));

			ks.load(fin, password.toCharArray());
			kmf.init(ks, password.toCharArray());

			context.init(kmf.getKeyManagers(), null, null);

			SSLSocketFactory socketFactory = context.getSocketFactory();

			// start a plain socket first to specify connect timeout.
			Socket socket = new Socket();
			socket.setKeepAlive(true);
			socket.connect(new InetSocketAddress(hostname, port), 10000);

			// ssl handshake
			SSLSocket ssocket = (SSLSocket) socketFactory.createSocket(socket, hostname, port, true);
			ssocket.startHandshake();

			System.out.println("[APN][" + certName + "], Connected to " + socket.getRemoteSocketAddress());
			return ssocket;
		} catch (Exception e) {
			System.out.println(e.getMessage() + e.getStackTrace());
			return null;
		}
	}

	public static Socket socket = null;

	public static String sendPost(String url, String param) {
		PrintWriter out = null;
		BufferedReader in = null;
		String result = "";
		try {
			URL realUrl = new URL(url);
			// 打开和URL之间的连接
			URLConnection conn = realUrl.openConnection();
			// 设置通用的请求属性
			conn.setConnectTimeout(2000);
			conn.setRequestProperty("accept", "*/*");
			conn.setRequestProperty("connection", "Keep-Alive");
			conn.setRequestProperty("user-agent", "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1;SV1)");
			conn.setRequestProperty("Content-Type", "application/raw");
			// 发送POST请求必须设置如下两行
			conn.setDoOutput(true);
			conn.setDoInput(true);
			// 获取URLConnection对象对应的输出流
			out = new PrintWriter(conn.getOutputStream());
			// 发送请求参数
			out.print(param);
			// flush输出流的缓冲
			out.flush();
			// 定义BufferedReader输入流来读取URL的响应
			in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
			String line;
			while ((line = in.readLine()) != null) {
				result += line;
			}
		} catch (Exception e) {
			System.out.println("发送 POST 请求出现异常！" + e);
			e.printStackTrace();
		}
		// 使用finally块来关闭输出流、输入流
		finally {
			try {
				if (out != null) {
					out.close();
				}
				if (in != null) {
					in.close();
				}
			} catch (IOException ex) {
				ex.printStackTrace();
			}
		}
		return result;
	}

	public static enum UsageNames {
		StreamGeneration(0),
		test(1),
		RoomGeneration(2),
		lala(3);
		
	    private final int value;
	    private UsageNames(int value) {
	        this.value = value;
	    }

	    public int getValue() {
	        return value;
	    }
	}
	

	
	public static Map<Integer, SkillBook> skillBooks;
	
	public static void SkillBookGame(Master master, Pet pet){
		Scanner scanner = new Scanner(System.in);
		System.out.println("Welcome " + master.name + " Currently you have " + master.money + " coins");
		System.out.println("our pet " + pet.name + " has skills :" + pet.petSkills);

		while(true){
		    System.out.print("(0 to exit) Enter your skill book id: ");
		    Integer bookId = Integer.parseInt(scanner.next());
		    if (bookId == 0) break;
		    trainPet(master, pet, bookId);
		}
		
		System.out.println("Game Over");
	}
	
	public static String getPetSkillDesc(Pet pet){
		List<String> skills = new LinkedList<String>();
		
		for (Integer i : pet.petSkills){
			skills.add(skillBooks.get(i).bookName);
		}
		
		return skills.toString();
	}
	
	public static void trainPet(Master master, Pet pet, Integer bookId){
		SkillBook skillBook = skillBooks.get(bookId);
		if (skillBook == null){
			System.out.println("Opps !!!  Don't have such skill book");
			return;
		}
		
		if (master.money < skillBook.price){
			System.out.println("Opps !!!  Sorry " + master.name + ", you don't have enough coins to purchase " + skillBooks.get(bookId).bookName);
			return;
		}
		
		if (hasSkill(pet, bookId)){
			System.out.println("Opps !!!  Sorry " + master.name + ", you pet already learned " + skillBooks.get(bookId).bookName);
			return;
		}
		
		master.money -= skillBook.price;
		learnSkill(pet, bookId);
		
		System.out.println("Train finished, your pet now learned " + getPetSkillDesc(pet));
		System.out.println("Your left coins " + master.money);
	}
	
	public static boolean hasSkill(Pet pet, int skillBookId){
		if (pet.petSkills.contains(skillBookId))
			return true;
		
		return false;
	}
	
	public static void learnSkill(Pet pet, int skillBookId){
		if (pet.petSkills.size() == 0){
			pet.petSkills.add(skillBookId);
			return;
		}
		
		Random r = new Random();
		int chance;
		switch (pet.petSkills.size()) {
		case 1:
			chance = 200;
			break;
		case 2:
			chance = 15;
			break;
		case 3:
			chance = 2;
			break;
		default:
			chance = 0;
			break;
		}
		
		if (r.nextInt(1000) < chance){
			pet.petSkills.add(skillBookId);
		}
		else{
			int toRemoveSkillId = 0, i = 0, flag = r.nextInt(pet.petSkills.size());
			
			for (Integer skill : pet.petSkills){
				if (flag == i++)
					toRemoveSkillId = skill;
			}			
			
			pet.petSkills.remove(toRemoveSkillId);
			pet.petSkills.add(skillBookId);
		}
	}
	
	static{
		skillBooks = new HashMap<Integer, SkillBook>();
		skillBooks.put(1, new SkillBook("幸运", 500));
		skillBooks.put(2, new SkillBook("高级幸运", 2000));
		skillBooks.put(3, new SkillBook("吸血攻击", 40000));
		skillBooks.put(4, new SkillBook("舍身", 150000));
		skillBooks.put(5, new SkillBook("毒牙撕咬", 12000));
		skillBooks.put(6, new SkillBook("再生", 500));
		skillBooks.put(7, new SkillBook("终极再生", 500));
		skillBooks.put(8, new SkillBook("高级必杀", 30000));
		skillBooks.put(9, new SkillBook("水击", 15000));
		skillBooks.put(10, new SkillBook("必杀", 10000));
		skillBooks.put(11, new SkillBook("飞行", 500));
		skillBooks.put(12, new SkillBook("高级飞行", 3000));
		skillBooks.put(13, new SkillBook("追击", 50000));
		skillBooks.put(14, new SkillBook("善恶有报", 180000));
		skillBooks.put(15, new SkillBook("灵敏", 500));
		skillBooks.put(16, new SkillBook("高级灵敏", 2000));
		skillBooks.put(17, new SkillBook("隐身", 500));
		skillBooks.put(18, new SkillBook("高级隐身", 2000));
		skillBooks.put(19, new SkillBook("强壮", 8000));
		skillBooks.put(20, new SkillBook("高级强壮", 50000));
		skillBooks.put(21, new SkillBook("侦查", 2000));
		skillBooks.put(22, new SkillBook("神佑", 500));
		skillBooks.put(23, new SkillBook("高级神佑", 100000));
	}
	
	public static void gameDemo(){
		Master master = new Master("奔跑的面包", 500000);
		Pet pet = new Pet("小企鹅", null);
		SkillBookGame(master, pet);
	}
	
	public static int genId32(){
		int serverId = 1;
		int base = 100000000;
		Long longId = System.currentTimeMillis() / 100 % base + serverId * base;
		int result = longId.intValue();
		
		synchronized (tsLock) {
			if (result <= maxId32)
				result = maxId32 + 1;
			
			maxId32 = result;
		}
		
		return result;
	}
	
	
	
	public static void main(String[] args) throws Exception{
		ExecutorService exe = Executors.newFixedThreadPool(50);
		
		for (int i = 0; i < 200000; i++)
			exe.submit(new Runnable() {
				
				@Override
				public void run() {
					try {
						testProdApi();
					} catch (JSONException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
					
				}
			});
		
		exe.awaitTermination(1, TimeUnit.HOURS);
	}
	
	public static void testProdApi() throws JSONException{
        JSONObject param = new JSONObject();
        param.put("sort_flag", 0);
        //param.put("category_id", 3);
        param.put("limit", 20);
		//String s = sendPost("http://127.0.0.1:50001/r/j/CONTENT_RECOMMEND/3/142574/0?_appid=weiwei", param.toString());
        String s = sendPost("http://192.168.128.130:9025/r/j/CONTENT_RECOMMEND/3/142574/0?_appid=weiwei", param.toString());
		System.out.println(s);
	}
	
	public static void testConnect() throws JSONException{
        JSONObject param = new JSONObject();
        param.put("room_id", 1);
        param.put("host_id", 2);
        param.put("flag", 3);
		String s = sendPost("http://192.168.128.130:9025/r/j/RINGS_BROADCAST/1/10007003/0?_appid=weiwei", param.toString());
		System.out.println(s);
		JSONObject resp = new JSONObject(s);
		long retStreamId = resp.getJSONObject("resp_get_stream_id").getLong("stream_id");
		System.out.println(retStreamId);
	}

	public static int i = 0;

	public static void testThreadFactory() throws InterruptedException {
		ExecutorService ser = Executors.newCachedThreadPool();

		Runnable a = new Runnable() {

			public void run() {
				try {
					Thread.sleep(new Random().nextInt(5000));
					System.out.println(i++);
				} catch (InterruptedException e) {
					System.out.println("Interrupted");
				}

			}
		};
		for (int i = 0; i < 100; i++) {
			ser.submit(a);
		}

		if (!ser.awaitTermination(3, TimeUnit.SECONDS))
			ser.shutdownNow();
	}

	public static void testAPN() throws InvalidSSLConfig, FileNotFoundException {
		final ApnsDelegate delegate = new ApnsDelegate() {
			public void messageSent(final ApnsNotification message, final boolean resent) {
				System.out.println("Sent message " + message + " Resent: " + resent);
			}

			public void messageSendFailed(final ApnsNotification message, final Throwable e) {
				System.out.println("Failed message " + message);

			}

			public void connectionClosed(final DeliveryError e, final int messageIdentifier) {
				System.out.println("Closed connection: " + messageIdentifier + "\n   deliveryError " + e.toString());
			}

			public void cacheLengthExceeded(final int newCacheLength) {
				System.out.println("cacheLengthExceeded " + newCacheLength);

			}

			public void notificationsResent(final int resendCount) {
				System.out.println("notificationResent " + resendCount);
			}

			public void messageSent(ApnsNotification arg0) {
				// TODO Auto-generated method stub

			}
		};

		final ApnsService svc = APNS.newService()
				// .withProductionDestination()
				// .withGatewayDestination("gateway.sandbox.push.apple.com",2195)
				.withSandboxDestination().withCert(new FileInputStream("e:\\test2.p12"), "123")
				// .withCert(new FileInputStream("e:\\test.p12"),"Mozat!@#$%")
				.withDelegate(delegate).build();

		final String goodToken = "8c327f902d4a056ff0a001677c3ddeedb10dd47ab557dc69340c0d202dc6630d";
		// "6d47b986aa372a3d8e0cf592a202db7ca9496836fe0e2766eed5a912b5c9dc44";
		// "f5d7f486160f1c8a8288dda9e0add4193ec0de0b6b4d4e76724b1f024ac69ce2";

		final String payload = APNS.newPayload().alertBody("Wrzlmbrmpf dummy alert 22222").build();

		svc.start();
		System.out.println("Sending message");
		svc.push(goodToken, payload);

		System.out.println("Getting inactive devices");
		final Map<String, Date> inactiveDevices = svc.getInactiveDevices();

		for (final Entry<String, Date> ent : inactiveDevices.entrySet()) {
			System.out.println("Inactive " + ent.getKey() + " at date " + ent.getValue());
		}

		System.out.println("Stopping service");
		svc.stop();
	}

	public static void testSocket(final Socket socket) {
		new Thread(new Runnable() {

			public void run() {
				byte[] input = new byte[6];
				Socket s = socket; // be sure to close the right socket at the
									// end
				String certName = "test";
				try {
					int result = new DataInputStream(socket.getInputStream()).read(input);
					if (result != -1) {
						ByteArrayInputStream bis = new ByteArrayInputStream(input);
						DataInputStream dis = new DataInputStream(bis);
						byte command = dis.readByte();
						byte status = dis.readByte();
						int id = dis.readInt();

						System.out.println("[APN][" + certName + "], Apple response: command=" + command + ", status="
								+ status + ", id=" + id);

						// Date: 2014-03-07
						// https://developer.apple.com/library/ios/documentation/NetworkingInternet/Conceptual/RemoteNotificationsPG/Chapters/CommunicatingWIthAPS.html#//apple_ref/doc/uid/TP40008194-CH101-SW1
						// If you send a notification that is accepted by APNs,
						// nothing is returned.
						// If you send a notification that is malformed or
						// otherwise unintelligible, APNs returns an
						// error-response packet and closes the connection.
						// Any notifications that you sent after the malformed
						// notification using the same connection are discarded,
						// and must be resent. Figure 5-2 shows the format of
						// the error-response packet.

					} else {
						System.out.println("[APN][" + certName + "], Connection to apple server is closed.");
					}

				} catch (IOException e) {
					System.out.println("[APN][" + certName + "], Reading thread error: " + e.getMessage());
				}

			}
		}).start();

	}

	static public void PoolTest() throws InterruptedException, ExecutionException {
		ThreadPoolExecutor exe = new ThreadPoolExecutor(2, 5, 5, TimeUnit.MINUTES, new LinkedBlockingQueue<Runnable>());

		Callable jobA = new Callable() {

			public Integer call() throws Exception {
				try {
					Thread.sleep(3000);
				} catch (InterruptedException e) {
					e.printStackTrace();
				}
				System.out.println("Test job A");

				return 5;
			}
		};

		Future<Integer> future = exe.submit(jobA);
		System.out.println(future.isDone());
		future.get();

		exe.shutdown();

	}

	static Map<String, Long> blackList = new ConcurrentHashMap<String, Long>();

	static private void TestInterval() {
		int blacklistMins = 30;
		final long blacklistStayPeriod = blacklistMins * 60 * 1000; // in mills

		new Thread(new Runnable() {

			public void run() {
				boolean interupted = false;
				while (!interupted) {
					try {

						for (Entry<String, Long> entry : blackList.entrySet()) {
							if (System.currentTimeMillis() > entry.getValue() + blacklistStayPeriod) {
								System.out.println("Remove " + entry.getKey() + " from blacklist");
								blackList.remove(entry.getKey());
							}
						}

						Thread.sleep(5000);
						int a = 3 / (5 * 0);
					} catch (InterruptedException e) {
						e.printStackTrace();
						interupted = true;
					}
				}
			}
		}).start();

		new Thread(new Runnable() {

			public void run() {
				boolean interupted = false;
				while (!interupted) {
					try {
						String server = null;
						try {
							server = "54.255.137.225";
							if (!blackList.containsKey(server)) {
								TestUsernamePassword(server);
							} else {
								System.out.println(server + " in blacklist, will not be processed.");
							}

						} catch (IOException e) {
							System.out.println("Put " + server + " in blacklist");
							blackList.put(server, System.currentTimeMillis());
						}

						Thread.sleep(2000);
					} catch (InterruptedException e) {
						interupted = true;
					}
				}
			}
		}).start();
	}

	static private void TestUsernamePassword(String serverIp) throws IOException {
		URL url = new URL("http://" + serverIp + ":8086/connectioncounts");
		// ("http://54.255.137.225:8080/wowzaLB");
		HttpURLConnection con = (HttpURLConnection) url.openConnection();

		Authenticator.setDefault(new Authenticator() {
			protected PasswordAuthentication getPasswordAuthentication() {
				return new PasswordAuthentication("mozat", "2ingsmozat".toCharArray());
			}
		});

		System.out.println(con.getResponseCode());
		BufferedReader br = new BufferedReader(new InputStreamReader(con.getInputStream()));
		String s = null;
		String cdns = "";
		while ((s = br.readLine()) != null) {
			cdns += s;
		}

		System.out.println(cdns);
	}
}
