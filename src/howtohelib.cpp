#include "FHE.h"
#include "EncryptedArray.h"
#include "EvalMap.h"
#include <NTL/BasicThreadPool.h>
/* Pour la fonction cputime */
#include <time.h>
#include <sys/time.h>

/*
 * renvoie le temps en secondes
 * renvoie le temps en secondes depuis t si t est donné en argument
 */
double cputime(const double before=0){
	return ((double)clock() / CLOCKS_PER_SEC)-before;
}
void rec(){
/* FIXING VARIABLES */
	 long values[2][19] = {
		// 80 bits
		{2,21168,27305,28,43,635,0,
		10796,26059,0,42,18,0,100,1,
		25,23,3,64},
		{ // 128 bits
		 /*p=*/2,/*phim=*/26400,/*m=*/27311,
		 /*d=*/55,/*m1=*/31,/*m2*/881,/*m3=*/0,
		 /*g1=*/21145,/*g2=*/1830,/*g3=*/0,
		 /*ord1=*/30,/*ord2=*/16,/*ord3=*/0,
		 /*c_m=*/100,/*r=*/1,/*L=*/25,/*B=*/23,
		 /*c=*/3,/*skHwt=*/64
		 }
	 };
	 // on copie les valeurs dans le tableau mValues
	 long mValues[19];
	 for (int v=0; v<19; v++){
		 mValues[v] = values[1][v]; // on utilise les paramètres pour 127 bits
	 }
    
    // on affiche la valeur de m
	cout << "m=" << mValues[2] << endl;

	Vec<long> mvec;
	vector<long> gens;
	vector<long> ords;

	int p = mValues[0];
	long phim = mValues[1];
	long m = mValues[2];
	// on s'assure que p est premier avec m
	assert(GCD(p, m) == 1);

	append(mvec, mValues[4]);
	if (mValues[5]>1) append(mvec, mValues[5]);
	if (mValues[6]>1) append(mvec, mValues[6]);
	gens.push_back(mValues[7]);
	if (mValues[8]>1) gens.push_back(mValues[8]);
	if (mValues[9]>1) gens.push_back(mValues[9]);
	ords.push_back(mValues[10]);
	if (abs(mValues[11])>1) ords.push_back(mValues[11]);
	if (abs(mValues[12])>1) ords.push_back(mValues[12]);
	int r = mValues[14],
		L = mValues[15],
		B = mValues[16],
		c = mValues[17],
		skHwt = mValues[18]
		;


/* COMPUTING CONTEXT AND PARAMETERS */
	cout << "Computing parameters ... " << flush;
	double t = cputime();
	FHEcontext context(m, p, r, gens, ords);
	context.bitsPerLevel = B;
	buildModChain(context, L, c);
	context.makeBootstrappable(mvec, 0, false);
	context.rcData.skHwt = skHwt;

	long nPrimes = context.numPrimes();
	IndexSet allPrimes(0,nPrimes-1);
	double bitsize = context.logOfProduct(allPrimes)/log(2.0);

	long p2r = context.alMod.getPPowR();
	context.zMStar.set_cM(mValues[13]/100.0);
	cout << cputime(t) << "s" << endl; // affiche le temps d'exécution pour calculer les paramètres

/* KEY GENERATION */
	cout << "Generating keys ... " << flush;
	t = cputime();
	FHESecKey secretKey(context);
	FHEPubKey& publicKey = secretKey;
	secretKey.GenSecKey(skHwt);      // A Hamming-weight-64 secret key
	addSome1DMatrices(secretKey); // compute key-switching matrices that we need
	addFrbMatrices(secretKey);
	secretKey.genRecryptData();
	cout << cputime(t) << "s" << endl; // affiche le temps d'exécution pour générer les clés
	cerr << "Security parameter: " << context.securityLevel() << endl;

	// permet de sauvegarder les clés dans des fichiers, pour les recharger plus tard
	ofstream seckey("secret.key", ofstream::out),
			 pubkey("public.key", ofstream::out);
	seckey << secretKey << endl;
	pubkey << publicKey << endl;
	seckey.close();
	pubkey.close();
	return;

/* INIT SUPPORT */
	EncryptedArray ea(context);
	NewPlaintextArray ptarray(ea),
					  ptarray1(ea),
					  ptarray2(ea);
	Ctxt c1(publicKey), c2(publicKey);
	encode(ea,ptarray,2);
	encode(ea,ptarray1,1);

/* BEGIN ENCRYPTION */
	cout << "Encryption ... " << flush;
	t = cputime();
	ea.encrypt(c1,publicKey,ptarray);
	ea.encrypt(c2,publicKey,ptarray1);
	cout << cputime(t) << "s" << endl; // affiche le temps pour chiffrer le vecteur

	cout << "Multiply ... " << flush;
	t = cputime();
	c1 *= c2;
	c1 *= c2;
	cout <<  cputime(t) << "s" << endl; // affiche le temps pour mutliplier les vecteurs 2 fois entre eux
	
	cout << "Recryption ... " << flush;
	t = cputime();
	publicKey.reCrypt(c1);
	cout <<  cputime(t) << "s" << endl; // affiche le temps pour rechiffrer un chiffré

/* BEGIN DECRYPTION */
	ea.decrypt(c1,secretKey,ptarray2);

/* CHECK RESULT */
	vector<long> before(ea.size()),
				after(ea.size());
	decode(ea,after,ptarray2);
	cout << after << endl;
}

int main(int argc, char *argv[])
{
/* Dans le cas où le multi-threading est activé, on initialise la pool */
#ifdef FHE_BOOT_THREADS
  unsigned int nthreads = 4;
  SetNumThreads(nthreads);
  cout << "*** nthreads = " << nthreads << endl;
#else
  cout << "*** no threads" << endl;
#endif
	rec();
	return 0;
}
