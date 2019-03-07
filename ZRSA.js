function ZRSA(){
this.publickey=undefined;
this.privatekey=undefined;
this.keylen=1000;
var isPrime=(num)=>{
	if(num == 2 || num == 3)
		return true;
	if(num%6!=1 && num%6!=5) 
		return false;
	let sqr=parseInt(Math.sqrt(num));
	for(let i=5;i<=sqr;i+=6)
		if(num%i==0 || num%(i+2)==0)
	return false;
	return true;	
	}
	
var getRandPrime=()=>{
	let x;
	do
	x=parseInt(this.keylen/10)+parseInt(Math.random()*this.keylen);
	while(!isPrime(x));
	return x;
}
var getRandPrimeSet=()=>{//get p,q
	let p;
	do
	p=getRandPrime();
	while(!isPrime((p-1)/2));
	let q;
	do
		q=getRandPrime();
	while(Math.abs(p-q)<this.keylen*0.1 || !isPrime((q-1)/2))//p,q距离太近会降低安全性
	return {p,q};
}
//一般情况,我们算fai N是极其困难的,而分解N为p,q后,算fai N是极其简单的
//RSA就是基于这一点使得加密简单,逆向困难
var gcd=(m,n)=>{//辗转相除法
	let a=Math.max(m,n);let b=Math.min(m,n);
	while(true)
	{
		let left=a%b;
		if(left==0)
			return b;
		else{
		a=b;
		b=left;
		}
	}
	
}
var isCoprime=(a,b)=>{//判断是否互质,效率很低
	return gcd(a,b)==1;
}
var fai=(x)=>{
	if(x==1)
		return 1;
	
	let ret=0;
	for(let i=2;i<x;i++)if(isCoprime(i,x))ret++;
	ret++;
	return ret;
}
var expmod=(a,b,c)=>{//可以解决a^b (mod c),即使数字a^b特别大,limit为输出允许的最大整数
	let ret=1;
	for(let i=0;i<b;i++)
	{ret*=a;
	ret-=parseInt(ret/c)*c;
	}
	return ret;
}

this.generateKeys=()=>{
	let pset=getRandPrimeSet();
	let {p,q}=pset;
	let N=p*q;
	let r=(p-1)*(q-1);//fai(N)
	
	let e;
	do
	e=parseInt(parseInt(r/100)+parseInt(Math.random()*parseInt(r/10)));
	while(!isCoprime(e,r) || e>r);
	
	let fair=((p-3)/2)*((q-3)/2);
	let d=expmod(e,fair-1,r)
	
	this.publickey={N,e};
	this.privatekey={N,d};
	
	//console.log(p,q,e,d,N);
	
}

this.encryptRaw=(m)=>{//使用公钥加密消息
	if(m<this.publickey.N)
	return expmod(m,this.publickey.e,this.publickey.N);
	else
	return undefined;
	
}
this.decryptRaw=(c)=>{//使用私钥解密消息
	return expmod(c,this.privatekey.d,this.privatekey.N);
}

this.encrypt=(m)=>{
	let d=Buffer.from(m);
	let en=Buffer.alloc(d.length*4);
	for(let i=0;i<d.length;i++)
		en.writeUInt32BE(this.encryptRaw(parseInt(d[i])),i*4);
	return en;
}

this.decrypt=(m)=>{
	let c=Buffer.from(m);
	let de=Buffer.alloc(c.length/4);
	for(let i=0;i<de.length;i++)
		de[i]=this.decryptRaw(c.readUInt32BE(i*4));
	
	
	return de;
}

}
console.log("此代码应配合日志学习\n")

let zrsa=new ZRSA();
zrsa.generateKeys();

let msg="Zhy的自实现RSA算法";
let en=zrsa.encrypt(msg);


console.log("公钥",zrsa.publickey);
console.log("私钥",zrsa.privatekey);

console.log("消息",Buffer.from(msg),"字符串:",msg);
console.log("公钥加密后",en);
console.log("私钥解密后",zrsa.decrypt(en),"字符串:",zrsa.decrypt(en)+"");

