function ZRSA(bits){//创建一个RSA-bits实例
var BN=require("./jsbn.js").BigInteger;
var crypto=require("crypto");

this.publickey=undefined;
this.privatekey=undefined;
this.bits=bits;

var possibleAprime=(num)=>{
	if(num.isEven())return false;
	if(!possibleAprime2(num))return false;
	if(!possibleAprime1(num,5))return false;

	return true;
	
	}
var getLargeNumber=(bn)=>{//[0,bn]	
	let ret=new BN('0');
	for(let i=0;i<bn.bitLength()-1;i++)
	ret=parseInt(Math.random()*2)==1?ret.setBit(new BN(i+"")):ret.clearBit(new BN(i+""));
	ret.setBit(bn.bitLength());
	ret.divide((new BN('0').setBit(bn.bitLength())).divide(bn))
	
	return ret;
}
var possibleAprime1=(x,checkTime)=>{//利用费马素性检测快速检测素数
	let ad=x.add(new BN('-2'));
	for(let i=0;i<checkTime;i++)
	{
		let a=getLargeNumber(ad).add(new BN('1'));
		if(a.modPow(x.add(new BN('-1')),x).compareTo(new BN('1'))!=0)
			return false;
	}	
	return true;
}

var possibleAprime2=(x)=>{
	//这个方法先生成了前1000个素数的乘积,若x与这个乘积的最大公因数是1,说明是素数的可能性更大了
	/*if(!this.primecheckcache[checkCount])
		for(let i=2;i<checkCount;i++)
			possibleAprime(,i)
		*/
	return x.gcd(new BN('24133')).compareTo(new BN('1'))==0;
}


var getLargeNumberBits=(bits)=>{
	let ret=new BN('0');
	for(let i=0;i<bits;i++)
	ret=parseInt(Math.random()*2)==1?ret.setBit(new BN(i+"")):ret.clearBit(new BN(i+""));
	ret=ret.setBit(new BN((bits-1)+""));
	return ret;
}
/*var getRandPrime=()=>{
	let x;
	do
	x=getLargeNumberBits(100);
	while(!possibleAprime(x));
	return x;
}*/
var getRandPrimeSet=()=>{//get p,q
	let p,q;
	do{
		do
		p=getLargeNumberBits(this.bits/2+12);
		while(!possibleAprime(p));	
		do
		q=getLargeNumberBits(this.bits/2-12);
		while(p.multiply(q).bitLength()!=this.bits || !possibleAprime(q));

	}
	while(false/*|| p.add(q.negate()).abs().compareTo(p.divide(new BN("10")))<0*/)
	return {p,q};
}
//一般情况,我们算fai N是极其困难的,而分解N为p,q后,算fai N是极其简单的
//RSA就是基于这一点使得加密简单,逆向困难

var isCoprime=(a,b)=>{//判断是否互质,效率很低
	return a.gcd(b)==1;
}
var isInteger=(x)=>{//判断是否整数
	return (x-parseInt(x))==0;
}
var fai=(x)=>{
	if(x==1)
		return 1;
	
	let ret=0;
	for(let i=2;i<x;i++)if(isCoprime(i,x))ret++;
	ret++;
	return ret;
}

this.generateKeys=()=>{
	
	let {p,q}=getRandPrimeSet();
	let N=p.multiply(q);
	let r=p.add(new BN("-1")).multiply(q.add(new BN("-1")));//fai(N)
	let e;
	do
	e=getLargeNumber(new BN("65537")).add(new BN("10000"));
	while(!isCoprime(e,r) || e.compareTo(r)>0);
	
	//let fair=((p-3)/2)*((q-3)/2);
	
	//let d=expmod(e,fair-1,r);
	let d=e.modInverse(r);

	console.log("p=",p+"");
	console.log("q=",q+"");
	console.log("N=",N+"","位数:",N.bitLength());
	
	this.publickey={N,e};
	this.privatekey={N,d};
	
}

this.encryptRaw=(m)=>{//使用公钥加密消息
	if(m.compareTo(this.publickey.N)<0)
	return (m.modPow(this.publickey.e,this.publickey.N));
	else
	return undefined;
	
}

this.decryptRaw=(c)=>{//使用私钥解密消息
	return (c.modPow(this.privatekey.d,this.privatekey.N));
}

this.encrypt=(m)=>{
	let d=Buffer.from(m);
	let en=Buffer.alloc(1024*10);
	let offset=0;
	for(let i=0;i<d.length;i++){
		let buf=Buffer.from(this.encryptRaw(new BN(d[i]+"")).toByteArray());
		en.writeUInt32BE(buf.length,offset);offset+=4;
		
		buf.copy(en,offset);offset+=buf.length;
	}
		en.writeUInt32BE(0,offset);offset+=4;
		en[offset]=0;offset+=1;
		
	return en.slice(0,offset);
}

this.decrypt=(m)=>{
	let d=Buffer.from(m);
	let de=Buffer.alloc(1024);
	let offset=0;let off=0;let buflen;
	do{
		buflen=d.readUInt32BE(offset);offset+=4;	
		de[off]=parseInt(this.decryptRaw(new BN(d.slice(offset,offset+buflen)))+"");offset+=buflen;
		
		off++;
	}while(buflen!=0)
	
	return de.slice(0,off-1);
}

}


let zrsa=new ZRSA(1024);
zrsa.generateKeys();
var BN=require("./jsbn.js").BigInteger;

let msg="Zhy自实现的RSA-1024算法";
let en=zrsa.encrypt(msg);
console.log(zrsa.decrypt(en)+"");

//console.log(zrsa.decryptRaw(zrsa.encryptRaw(new BN("123")))+"")
console.log("公钥","{e:"+zrsa.publickey.e+"}");
console.log("私钥","{d:"+zrsa.privatekey.d+"}");

console.log("消息",Buffer.from(msg));
console.log("公钥加密后",en);
console.log("私钥解密后",zrsa.decrypt(en),"字符串:",zrsa.decrypt(en)+"");
