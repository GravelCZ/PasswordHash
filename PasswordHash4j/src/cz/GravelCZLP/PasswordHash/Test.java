package cz.GravelCZLP.PasswordHash;

public class Test {

	public static String PasswordTotest = "P4ssw0rd1"; // if this is your password, go change it :D
	
	public static void main(String[] args) {
		TestHashv2();
	}
	
	private static void TestHashv2() {
		System.out.println("Running Test of Password Hash v2!");
		System.out.println("Testing password: " + PasswordTotest);
		PasswordHashv2 phv2 = new PasswordHashv2();
		String genhash = phv2.hash(PasswordTotest);
		System.out.println("Generated Hash: " + genhash);
		boolean auth = phv2.auth(PasswordTotest, genhash);
		System.out.println("Result:" + auth);
		System.out.println("Finished Test of Password Hash v2");
		phv2 = null; //DO NOT FORGET THIS, THIS REMOVES THE PASSWORD,HASH,ETC FROM RAM/MEMORY/HEAP/WHATEVER
	}
}
