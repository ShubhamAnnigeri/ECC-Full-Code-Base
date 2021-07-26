//Change Base point to (1,5) and use the order n=37. Check on wikipedia for the condition on choosing a base point.

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>

//Information about the curve and finite field

int a=1;//4;//coefficient for elliptic curve
int b=23;//20;//coefficient for elliptic curve
int p=991;//29;//prime number to provide finite field

//int points[1000][2];//to store a set of points satisfying the curve
int alpha[256][2];

//Information required for Encryption and Decryption
int encmsg[50][4];//to store the encrypted set of points
int decmsg[50][2];//to store the decrypted string

//Private Information
int PrivKey=12;//Private Key of Receiver

//Public Information
int PubKey[2]={0,0};//Public key of Receiver
int random=0;//Random Number required for Encoding
int Pbase[2]={0,0};//Base point for all operations
int Pbase1[2]={0,0};//Base point for signature

//Encrypted Point
int Enc[4]={0,0,0,0};

//Functions Used
int * sclr_mult(int k,int point[2]);
int * add(int A[2],int B[2]);
int inverse(int num);
int inverse1(int num);
int * encode(int m[2],int Pb[2],int random,int Pbase[2]);//(Message,Public Key)
int * genKey(int X,int P[2]);//(Private Key,Base Point)
int * decode(int Enc[4],int PrivKey);//(Encrypted Message, Private key of the Receiver) Outputs Message
void generate();//This function generates points on the curve and stores it in the points array
void map();//This is a test function to map the 26 alphabets onto some points on the curve
int isPAI(int *point);//Checks if the given point is the point at infinity
int* getPAI(int *point);//Returns point at infinity as the output
int * genSig(int PrivKey,int m);//To generate digital signature of the Server
int verifySig(int PubKey[2],int m,int P[2]);//Function to verify if the signature is right or not

int main()
{
    int *temp;
    random=(rand()%6)+3;
    //generate();
    map();


    printf("\nThe Mapped Points are : \n");
    for(int i=0;i<256;i=i+2)
    {
        printf("%d,%d,  ",alpha[i][0],alpha[i][1]);
    }

    int message[]={128,192,255,0,50,200},decrypted[50];

    //printf("Please enter your message (50 characters)\n:");
    //scanf("%u",&message[i]);

    Pbase[0]=1;//Deciding the base point here
    Pbase[1]=5;
    //int *temp;//Uncomment when you change code snippet
    temp=genKey(PrivKey,Pbase);
    PubKey[0]=*temp;
    PubKey[1]=*(temp+1);

    //ENCODING PROCESS
    for(int i=0;i<(sizeof(message)/sizeof(int));i++)
    {
        int x=(message[i]);
        //printf("\nFirst One = %d\n",x);
        int P[2];
        P[0]=alpha[x][0];
        P[1]=alpha[x][1];

        Pbase[0]=1;//Deciding the base point here
        Pbase[1]=5;
        temp=genKey(PrivKey,Pbase);
        PubKey[0]=*temp;
        PubKey[1]=*(temp+1);
        Pbase[0]=1;//Deciding the base point here
        Pbase[1]=5;

        //printf("\nPoint for it is = (%d,%d)\n",alpha[x][0],alpha[x][1]);

        temp=encode(P,PubKey,random,Pbase);

        encmsg[i][0]=*(temp);
        encmsg[i][1]=*(temp+1);
        encmsg[i][2]=*(temp+2);
        encmsg[i][3]=*(temp+3);
        //printf("\nThe encoded point is [(%d,%d),(%d,%d)]\n",encmsg[i][0],encmsg[i][1],encmsg[i][2],encmsg[i][3]);
    }
    /*
    //For Displaying the encrypted string
    for(int i=0;i<2*strlen(message);i+=2)
    {
        for(int j=0;j<10;j++)//Loop for searching character the point is mapped to
        {
            if(alpha[j][0]==encmsg[i][0] && alpha[j][1]==decmsg[i][1])
            {
                encrypted[i]='0'+j;
            }
            if(alpha[j][0]==encmsg[i][2] && alpha[j][1]==decmsg[i][3])
            {
                encrypted[i+1]='0'+j;
            }
        }
    }
    */

    //DECODING PROCESS
    for(int i=0;i<(sizeof(message)/sizeof(int));i++)
    {
        int P[4];
        P[0]=encmsg[i][0];
        P[1]=encmsg[i][1];
        P[2]=encmsg[i][2];
        P[3]=encmsg[i][3];
        //printf("\nThe encoded point is [(%d,%d),(%d,%d)]\n",encmsg[i][0],encmsg[i][1],encmsg[i][2],encmsg[i][3]);

        temp=genKey(PrivKey,Pbase);
        PubKey[0]=*temp;
        PubKey[1]=*(temp+1);
        Pbase[0]=1;//Deciding the base point here
        Pbase[1]=5;
        //printf("\nPrivate Key is %d\n",PrivKey);
        temp=decode(P,PrivKey);
        decmsg[i][0]=*temp;
        decmsg[i][1]=*(temp+1);
        //printf("\nDecoded set of points are:(%d,%d)\n",decmsg[i][0],decmsg[i][1]);

        for(int j=0;j<256;j++)//Loop for searching character the point is mapped to
        {
            if(alpha[j][0]==decmsg[i][0] && alpha[j][1]==decmsg[i][1])
            {
                decrypted[i]=j;
            }
        }
    }
    //decrypted[strlen(message)]='\0';
    printf("The decrypted message is \n\n");
    for(int i=0;i<(sizeof(message)/sizeof(int));i++)
        printf("\n%u",decrypted[i]);

    Pbase1[0]=1;//Deciding the base point here
    Pbase1[1]=5;
    temp=genKey(PrivKey,Pbase1);
    PubKey[0]=*temp;
    PubKey[1]=*(temp+1);
    Pbase1[0]=1;//Deciding the base point here
    Pbase1[1]=5;

    temp=genSig(PrivKey,4);
    int C[2]={0,0};
    C[0]=*temp;
    C[1]=*(temp+1);
    printf("The Signature is (%d,%d)\n\n",C[0],C[1]);

    Pbase1[0]=1;//Deciding the base point here
    Pbase1[1]=5;
    temp=genKey(PrivKey,Pbase);
    PubKey[0]=*temp;
    PubKey[1]=*(temp+1);
    Pbase1[0]=1;//Deciding the base point here
    Pbase1[1]=5;

    if (verifySig(PubKey,4,C))
        printf("\nVerified\n");
    else
        printf("\nRejected\n");

    /*
    int P[2];
    temp=sclr_mult(random,Pbase);
    P[0]=*temp;
    P[1]=*(temp+1);

    Pbase[0]=points[5][0];//Deciding the base point here
    Pbase[1]=points[5][1];
    int Q[2];
    temp=sclr_mult(random,PubKey);
    Q[0]=*temp;
    Q[1]=*(temp+1);

    int R[2];
    temp=add(message,Q);
    R[0]=*temp;
    R[1]=*(temp+1);

    printf("The encrypted point is [(%d,%d),(%d,%d)]\n",P[0],P[1],R[0],R[1]);

    temp=sclr_mult(PrivKey,P);
    int O[2];
    O[0]=*temp;
    O[1]=p-*(temp+1);

    temp=add(R,O);
    O[0]=*temp;
    O[1]=*(temp+1);
    printf("The message point is (%d,%d)\n",O[0],O[1]);
    */
    /*
    int P[2];
    temp=add(points[27],points[22]);
    P[0]=*temp;
    P[1]=p-*(temp+1);
    printf("The point after addition is (%d,%d)",P[0],P[1]);
    */
    /*
    temp=sclr_mult(2,points[2]);
    //temp=add(points[1],points[1]);
    P[0]=*temp;
    P[1]=*(temp+1);
    printf("The point after doubling is (%d,%d)",P[0],P[1]);
    */

    /*
    //Working Code
    Pbase[0]=3;//Deciding the base point here
    Pbase[1]=28;

    temp=genKey(PrivKey,Pbase);
    PubKey[0]=*temp;
    PubKey[1]=*(temp+1);
    printf("\nThe Public Key is (%d,%d)\n",PubKey[0],PubKey[1]);

    int message[2];
    message[0]=points[18][0];
    message[1]=points[18][1];
    printf("The message point is (%d,%d)\n",message[0],message[1]);

    Pbase[0]=3;//Deciding the base point here
    Pbase[1]=28;

    temp=genKey(PrivKey,Pbase);
    PubKey[0]=*temp;
    PubKey[1]=*(temp+1);

    //Not being used currently
    //int message=7;
    //printf("The message is %d",message);

    Pbase[0]=3;//Deciding the base point here
    Pbase[1]=28;
    temp=encode(message,PubKey,random,Pbase);
    Enc[0]=*(temp);
    Enc[1]=*(temp+1);
    Enc[2]=*(temp+2);
    Enc[3]=*(temp+3);

    printf("\nThe Encrypted Point is [(%d,%d) , (%d,%d)]",Enc[0],Enc[1],Enc[2],Enc[3]);

    int m[2];
    Pbase[0]=3;//Deciding the base point here
    Pbase[1]=28;
    temp=decode(Enc,PrivKey);
    m[0]=*temp;
    m[1]=*(temp+1);
    printf("\nThe Decrypted Message point is (%d,%d)\n",m[0],m[1]);
    */
    return 0;
}

int * sclr_mult(int k,int P[2])//using LSB first algorithm
{
    int *temp,i;
    int *Q = calloc(2,sizeof(int));
    Q[0]=0;
    Q[1]=0;
    for(i=31;i>=0;i--)
    {
        if((k>>i)&1)
            break;
    }
    //printf("\n%d\n",i);
    for(int j=0;j<=i;j++)
    {
        if((k>>j)&1)
        {
            temp=add(Q,P);
            Q[0]=*temp;
            Q[1]=*(temp+1);
        }
        temp=add(P,P);
        P[0]=*temp;
        P[1]=*(temp+1);
    }
    return Q;
}

int * add(int A[2],int B[2])
{
    //printf("\nA=(%d,%d)\nB=(%d,%d)\n",A[0],A[1],B[0],B[1]);
    int *C = calloc(2,sizeof(int));
    long long int x=0,l=0;         //int C[2];
    if (isPAI(A) && isPAI(B))  // PAI + PAI = PAI
    {
        return getPAI(C);
    }
    if (A[0]==0 && A[1]==0)
    {
        return B;
    }
    if (B[0]==0 && B[1]==0)
    {
        return A;
    }
    //if (A[1]==(p-B[1]))
    //{
    //    return C;
    //}
    if ((A[0]==B[0]) && (A[1]==B[1]))
    {
        if (A[1] % p == 0)              // Vertical tangent
        {
            return getPAI(C);
        }
        x=((3*(A[0]*A[0]))+a)*inverse(2*A[1]);
        l=((x*x)-(2*A[0]))%p;
        C[0]=l;
        l=((x*(A[0]-C[0]))-A[1])%p;
        C[1]=l;
        /*
        x=((3*(A[0]*A[0]))+a)*inverse(2*A[1]);
        C[0]=((x*x)-(2*A[0]))%p;
        C[1]=((x*(A[0]-C[0]))-A[1])%p;
        */
        //C[0]=((A[0]*A[0])%p+(b*inverse(A[0]*A[0]))%p)%p;//For Binary Curves
        //C[1]=((A[0]*A[0])%p+((A[0]+(A[1]*inverse(A[0]))*C[0]))%p+(C[0])%p)%p;//For Binary Curves
    }
    else
    {
        if ((B[0] - A[0]) % p == 0)    // Vertical secant
        {
            return getPAI(C);
        }
        x=(B[1]-A[1])*inverse(B[0]-A[0]);
        l=((x*x)-(A[0]+B[0]))%p;
        //printf("\nl=%lld",l);
        C[0]=l;
        l=((x*(A[0]-C[0]))-A[1])%p;
        C[1]=l;
        /*
        x=(B[1]-A[1])*inverse(B[0]-A[0]);
        C[0]=((x*x)-(A[0]+B[0]))%p;
        C[1]=((x*(A[0]-C[0]))-A[1])%p;
        */
        //printf("\nThis is being executed  %d\n");
        //C[0]=((((A[1]+B[1])*inverse(A[0]+B[0]))*((A[1]+B[1])*inverse(A[0]+B[0])))%p + ((A[1]+B[1])*inverse(A[0]+B[0]))%p + A[0]%p + B[0]%p + a%p)%p;//For Binary Curves
        //C[1]=((((A[1]+B[1])*inverse(A[0]+B[0]))*(A[0]+C[0]))+C[0]+A[1])%p;//For Binary Curves
    }
    if (C[0]<0)
        C[0]=p+C[0];
    if (C[1]<0)
        C[1]=p+C[1];
    return C;
}

int isPAI(int *point)
{
    return ((point[0]==0) && (point[1]==0));
}

int* getPAI(int *point)
{
    point[0] = 0;
    point[1] = 0;
    return point;
}

int inverse(int num)
{
    int i=1;
    if (num<0)
        num=p+num;
    for (i=1;i<p;i++)
    {
        if(((num*i)%p)==1)
            break;
    }
    //printf("inverse=%d,%d",i,num);
    return i;
}

int inverse1(int num)
{
    int i=1;
    int n=997;
    if (num<0)
        num=n+num;
    for (i=1;i<n;i++)
    {
        if(((num*i)%n)==1)
            break;
    }
    //printf("inverse=%d,%d",i,num);
    return i;
}

/*
void generate()
{
    int rhs,lhs,i=0;//to find set of points that satisfy the elliptic curve
    for(int x=0;x<p;x++)
    {
        rhs=((x*x*x)+(a*x)+b)%p;
        for(int y=0;y<p;y++)
        {
            lhs=(y*y)%p;
            if (lhs==rhs)
            {
                points[i][0]=x;
                points[i][1]=y;
                i+=1;
            }
        }
    }
    printf("\nNumber of points found on the curve is %d \n",i);
    for(int k=0;k<i;k++)
    {
        printf("%d(%d,%d)\n",(k),points[k][0],points[k][1]);
    }
}
*/

int * genKey(int X,int P[2])
{
    int *temp;
    int *Q = calloc(2,sizeof(int));
    temp=sclr_mult(X,P);
    Q[0]=*temp;
    Q[1]=*(temp+1);
    return Q;
}

int * encode(int m[2],int Pb[2],int random,int Pbase[2])
{

    int Pm[2]={0,0};
    int *out = calloc(4,sizeof(int));
    /*
    for(int i=1;i<random;i++)
    {
        x=((m*random)+i)%p;
        fnum=sqrt(((x*x*x)+(a*x)+b)%p);
        num=fnum;
        if(num==fnum)
        {
            y=num;
            break;
        }
    }
    */
    Pm[0]=m[0];
    Pm[1]=m[1];

    //printf("\n\nMessage point is (%d,%d)",Pm[0],Pm[1]);
    int *temp,*temp2,temp1[2];

    temp=sclr_mult(random,Pb);
    temp1[0]=*temp;
    temp1[1]=*(temp+1);

    temp2=add(Pm,temp1);
    temp=sclr_mult(random,Pbase);

    out[0]=*temp;
    out[1]=*(temp+1);
    out[2]=*temp2;
    out[3]=*(temp2+1);
    //printf("\n\n %d,%d",out[2],out[3]);
    return out;
}

int * decode(int Enc[4],int PrivKey)
{
    int pt1[2],pt2[2],buf[2];
    int *x = calloc(2,sizeof(int));
    int *temp;
    pt1[0]=Enc[0];
    pt1[1]=Enc[1];
    pt2[0]=Enc[2];
    pt2[1]=Enc[3];

    temp=sclr_mult(PrivKey,pt1);
    buf[0]=*temp;
    buf[1]=*(temp+1);
    buf[1]=p-buf[1];

    temp=add(pt2,buf);
    x[0]=*temp;
    x[1]=*(temp+1);
    //=printf("Received is %d",x);
    //m=floor((x-1)*inverse(random));
    return x;
}

void map()//Over here I am just applying a continuous set of points. In actual I will assign randomly
{
    //int temp[2];
/*
for(int i=0;i<10;i++)
    {
        alpha[i][0]=points[3+i][0];
        alpha[i][1]=points[3+i][1];
    }
*/
        alpha[0][0]=1;
        alpha[0][1]=5;

        alpha[1][0]=2;
        alpha[1][1]=32;

        alpha[2][0]=3;
        alpha[2][1]=130;

        alpha[3][0]=6;
        alpha[3][1]=441;

        alpha[4][0]=8;
        alpha[4][1]=279;

        alpha[5][0]=10;
        alpha[5][1]=318;

        alpha[6][0]=14;
        alpha[6][1]=166;

        alpha[7][0]=16;
        alpha[7][1]=366;

        alpha[8][0]=24;
        alpha[8][1]=227;

        alpha[9][0]=25;
        alpha[9][1]=295;

        alpha[10][0]=27;
        alpha[10][1]=367;

        alpha[11][0]=33;
        alpha[11][1]=351;

        alpha[12][0]=35;
        alpha[12][1]=487;

        alpha[13][0]=36;
        alpha[13][1]=78;

        alpha[14][0]=37;
        alpha[14][1]=90;

        alpha[15][0]=38;
        alpha[15][1]=449;

        alpha[16][0]=40;
        alpha[16][1]=215;

        alpha[17][0]=45;
        alpha[17][1]=383;

        alpha[18][0]=52;
        alpha[18][1]=199;

        alpha[19][0]=54;
        alpha[19][1]=178;

        alpha[20][0]=56;
        alpha[20][1]=85;

        alpha[21][0]=59;
        alpha[21][1]=18;

        alpha[22][0]=60;
        alpha[22][1]=189;

        alpha[23][0]=62;
        alpha[23][1]=116;

        alpha[24][0]=67;
        alpha[24][1]=243;

        alpha[25][0]=73;
        alpha[25][1]=399;

        alpha[26][0]=83;
        alpha[26][1]=71;

        alpha[27][0]=91;
        alpha[27][1]=67;

        alpha[28][0]=99;
        alpha[28][1]=362;

        alpha[29][0]=102;
        alpha[29][1]=178;

        alpha[30][0]=107;
        alpha[30][1]=96;

        alpha[31][0]=116;
        alpha[31][1]=214;

        alpha[32][0]=123;
        alpha[32][1]=104;

        alpha[33][0]=130;
        alpha[33][1]=95;

        alpha[34][0]=142;
        alpha[34][1]=80;

        alpha[35][0]=145;
        alpha[35][1]=390;

        alpha[36][0]=151;
        alpha[36][1]=58;

        alpha[37][0]=160;
        alpha[37][1]=484;

        alpha[38][0]=170;
        alpha[38][1]=117;

        alpha[39][0]=176;
        alpha[39][1]=22;

        alpha[40][0]=178;
        alpha[40][1]=90;

        alpha[41][0]=200;
        alpha[41][1]=62;

        alpha[42][0]=251;
        alpha[42][1]=78;

        alpha[43][0]=259;
        alpha[43][1]=7;

        alpha[44][0]=274;
        alpha[44][1]=54;

        alpha[45][0]=277;
        alpha[45][1]=16;

        alpha[46][0]=294;
        alpha[46][1]=85;

        alpha[47][0]=309;
        alpha[47][1]=30;

        alpha[48][0]=310;
        alpha[48][1]=99;

        alpha[49][0]=314;
        alpha[49][1]=399;

        alpha[50][0]=316;
        alpha[50][1]=483;

        alpha[51][0]=318;
        alpha[51][1]=206;

        alpha[52][0]=320;
        alpha[52][1]=267;

        alpha[53][0]=331;
        alpha[53][1]=58;

        alpha[54][0]=332;
        alpha[54][1]=434;

        alpha[55][0]=336;
        alpha[55][1]=94;

        alpha[56][0]=338;
        alpha[56][1]=50;

        alpha[57][0]=339;
        alpha[57][1]=373;

        alpha[58][0]=343;
        alpha[58][1]=38;

        alpha[59][0]=345;
        alpha[59][1]=211;

        alpha[60][0]=346;
        alpha[60][1]=119;

        alpha[61][0]=349;
        alpha[61][1]=408;

        alpha[62][0]=352;
        alpha[62][1]=237;

        alpha[63][0]=353;
        alpha[63][1]=53;

        alpha[64][0]=357;
        alpha[64][1]=330;

        alpha[65][0]=358;
        alpha[65][1]=28;

        alpha[66][0]=361;
        alpha[66][1]=448;

        alpha[67][0]=362;
        alpha[67][1]=46;

        alpha[68][0]=365;
        alpha[68][1]=46;

        alpha[69][0]=367;
        alpha[69][1]=202;

        alpha[70][0]=371;
        alpha[70][1]=363;

        alpha[71][0]=374;
        alpha[71][1]=240;

        alpha[72][0]=375;
        alpha[72][1]=41;

        alpha[73][0]=376;
        alpha[73][1]=226;

        alpha[74][0]=377;
        alpha[74][1]=376;

        alpha[75][0]=380;
        alpha[75][1]=261;

        alpha[76][0]=381;
        alpha[76][1]=342;

        alpha[77][0]=383;
        alpha[77][1]=74;

        alpha[78][0]=388;
        alpha[78][1]=199;

        alpha[79][0]=391;
        alpha[79][1]=316;

        alpha[80][0]=393;
        alpha[80][1]=426;

        alpha[81][0]=396;
        alpha[81][1]=448;

        alpha[82][0]=397;
        alpha[82][1]=431;

        alpha[83][0]=400;
        alpha[83][1]=112;

        alpha[84][0]=403;
        alpha[84][1]=136;

        alpha[85][0]=411;
        alpha[85][1]=162;

        alpha[86][0]=414;
        alpha[86][1]=166;

        alpha[87][0]=418;
        alpha[87][1]=440;

        alpha[88][0]=422;
        alpha[88][1]=149;

        alpha[89][0]=426;
        alpha[89][1]=18;

        alpha[90][0]=429;
        alpha[90][1]=252;

        alpha[91][0]=431;
        alpha[91][1]=198;

        alpha[92][0]=439;
        alpha[92][1]=486;

        alpha[93][0]=441;
        alpha[93][1]=97;

        alpha[94][0]=444;
        alpha[94][1]=196;

        alpha[95][0]=447;
        alpha[95][1]=47;

        alpha[96][0]=448;
        alpha[96][1]=411;

        alpha[97][0]=450;
        alpha[97][1]=118;

        alpha[98][0]=453;
        alpha[98][1]=373;

        alpha[99][0]=463;
        alpha[99][1]=308;

        alpha[100][0]=464;
        alpha[100][1]=244;

        alpha[101][0]=466;
        alpha[101][1]=299;

        alpha[102][0]=467;
        alpha[102][1]=297;

        alpha[103][0]=468;
        alpha[103][1]=143;

        alpha[104][0]=470;
        alpha[104][1]=135;

        alpha[105][0]=471;
        alpha[105][1]=23;

        alpha[106][0]=473;
        alpha[106][1]=954;

        alpha[107][0]=476;
        alpha[107][1]=374;

        alpha[108][0]=478;
        alpha[108][1]=446;

        alpha[109][0]=479;
        alpha[109][1]=29;

        alpha[110][0]=481;
        alpha[110][1]=519;

        alpha[111][0]=484;
        alpha[111][1]=737;

        alpha[112][0]=487;
        alpha[112][1]=108;

        alpha[113][0]=489;
        alpha[113][1]=40;

        alpha[114][0]=494;
        alpha[114][1]=370;

        alpha[115][0]=495;
        alpha[115][1]=369;

        alpha[116][0]=496;
        alpha[116][1]=257;

        alpha[117][0]=497;
        alpha[117][1]=175;

        alpha[118][0]=498;
        alpha[118][1]=34;

        alpha[119][0]=499;
        alpha[119][1]=970;

        alpha[120][0]=501;
        alpha[120][1]=402;

        alpha[121][0]=502;
        alpha[121][1]=589;

        alpha[122][0]=504;
        alpha[122][1]=449;

        alpha[123][0]=506;
        alpha[123][1]=973;

        alpha[124][0]=507;
        alpha[124][1]=921;

        alpha[125][0]=508;
        alpha[125][1]=767;

        alpha[126][0]=509;
        alpha[126][1]=933;

        alpha[127][0]=512;
        alpha[127][1]=977;

        alpha[128][0]=514;
        alpha[128][1]=660;

        alpha[129][0]=515;
        alpha[129][1]=327;

        alpha[130][0]=518;
        alpha[130][1]=803;

        alpha[131][0]=520;
        alpha[131][1]=932;

        alpha[132][0]=521;
        alpha[132][1]=719;

        alpha[133][0]=522;
        alpha[133][1]=947;

        alpha[134][0]=523;
        alpha[134][1]=296;

        alpha[135][0]=524;
        alpha[135][1]=6;

        alpha[136][0]=527;
        alpha[136][1]=31;

        alpha[137][0]=531;
        alpha[137][1]=561;

        alpha[138][0]=535;
        alpha[138][1]=575;

        alpha[139][0]=536;
        alpha[139][1]=446;

        alpha[140][0]=537;
        alpha[140][1]=743;

        alpha[141][0]=538;
        alpha[141][1]=368;

        alpha[142][0]=539;
        alpha[142][1]=644;

        alpha[143][0]=540;
        alpha[143][1]=40;

        alpha[144][0]=544;
        alpha[144][1]=300;

        alpha[145][0]=545;
        alpha[145][1]=650;

        alpha[146][0]=546;
        alpha[146][1]=161;

        alpha[147][0]=547;
        alpha[147][1]=338;

        alpha[148][0]=551;
        alpha[148][1]=199;

        alpha[149][0]=552;
        alpha[149][1]=103;

        alpha[150][0]=553;
        alpha[150][1]=129;

        alpha[151][0]=554;
        alpha[151][1]=15;

        alpha[152][0]=555;
        alpha[152][1]=987;

        alpha[153][0]=558;
        alpha[153][1]=334;

        alpha[154][0]=560;
        alpha[154][1]=306;

        alpha[155][0]=562;
        alpha[155][1]=363;

        alpha[156][0]=563;
        alpha[156][1]=166;

        alpha[157][0]=566;
        alpha[157][1]=69;

        alpha[158][0]=567;
        alpha[158][1]=463;

        alpha[159][0]=570;
        alpha[159][1]=165;

        alpha[160][0]=572;
        alpha[160][1]=22;

        alpha[161][0]=577;
        alpha[161][1]=595;

        alpha[162][0]=579;
        alpha[162][1]=414;

        alpha[163][0]=580;
        alpha[163][1]=249;

        alpha[164][0]=582;
        alpha[164][1]=633;

        alpha[165][0]=583;
        alpha[165][1]=480;

        alpha[166][0]=586;
        alpha[166][1]=465;

        alpha[167][0]=589;
        alpha[167][1]=708;

        alpha[168][0]=590;
        alpha[168][1]=283;

        alpha[169][0]=591;
        alpha[169][1]=284;

        alpha[170][0]=592;
        alpha[170][1]=286;

        alpha[171][0]=596;
        alpha[171][1]=45;

        alpha[172][0]=599;
        alpha[172][1]=872;

        alpha[173][0]=601;
        alpha[173][1]=186;

        alpha[174][0]=604;
        alpha[174][1]=399;

        alpha[175][0]=606;
        alpha[175][1]=534;

        alpha[176][0]=610;
        alpha[176][1]=865;

        alpha[177][0]=611;
        alpha[177][1]=488;

        alpha[178][0]=612;
        alpha[178][1]=502;

        alpha[179][0]=615;
        alpha[179][1]=820;

        alpha[180][0]=620;
        alpha[180][1]=739;

        alpha[181][0]=621;
        alpha[181][1]=60;

        alpha[182][0]=622;
        alpha[182][1]=70;

        alpha[183][0]=626;
        alpha[183][1]=388;

        alpha[184][0]=629;
        alpha[184][1]=603;

        alpha[185][0]=631;
        alpha[185][1]=54;

        alpha[186][0]=633;
        alpha[186][1]=304;

        alpha[187][0]=638;
        alpha[187][1]=777;

        alpha[188][0]=641;
        alpha[188][1]=85;

        alpha[189][0]=644;
        alpha[189][1]=79;

        alpha[190][0]=647;
        alpha[190][1]=219;

        alpha[191][0]=649;
        alpha[191][1]=103;

        alpha[192][0]=651;
        alpha[192][1]=222;

        alpha[193][0]=652;
        alpha[193][1]=368;

        alpha[194][0]=654;
        alpha[194][1]=142;

        alpha[195][0]=656;
        alpha[195][1]=62;

        alpha[196][0]=657;
        alpha[196][1]=680;

        alpha[197][0]=658;
        alpha[197][1]=79;

        alpha[198][0]=661;
        alpha[198][1]=351;

        alpha[199][0]=665;
        alpha[199][1]=453;

        alpha[200][0]=667;
        alpha[200][1]=132;

        alpha[201][0]=672;
        alpha[201][1]=927;

        alpha[202][0]=676;
        alpha[202][1]=310;

        alpha[203][0]=678;
        alpha[203][1]=211;

        alpha[204][0]=680;
        alpha[204][1]=79;

        alpha[205][0]=682;
        alpha[205][1]=442;

        alpha[206][0]=687;
        alpha[206][1]=345;

        alpha[207][0]=688;
        alpha[207][1]=44;

        alpha[208][0]=693;
        alpha[208][1]=607;

        alpha[209][0]=696;
        alpha[209][1]=818;

        alpha[210][0]=700;
        alpha[210][1]=196;

        alpha[211][0]=704;
        alpha[211][1]=78;

        alpha[212][0]=707;
        alpha[212][1]=20;

        alpha[213][0]=708;
        alpha[213][1]=611;

        alpha[214][0]=715;
        alpha[214][1]=47;

        alpha[215][0]=722;
        alpha[215][1]=43;

        alpha[216][0]=724;
        alpha[216][1]=93;

        alpha[217][0]=728;
        alpha[217][1]=10;

        alpha[218][0]=734;
        alpha[218][1]=164;

        alpha[219][0]=739;
        alpha[219][1]=277;

        alpha[220][0]=742;
        alpha[220][1]=131;

        alpha[221][0]=744;
        alpha[221][1]=41;

        alpha[222][0]=747;
        alpha[222][1]=8;

        alpha[223][0]=754;
        alpha[223][1]=53;

        alpha[224][0]=756;
        alpha[224][1]=7;

        alpha[225][0]=759;
        alpha[225][1]=145;

        alpha[226][0]=761;
        alpha[226][1]=101;

        alpha[227][0]=767;
        alpha[227][1]=96;

        alpha[228][0]=771;
        alpha[228][1]=33;

        alpha[229][0]=772;
        alpha[229][1]=44;

        alpha[230][0]=774;
        alpha[230][1]=98;

        alpha[231][0]=776;
        alpha[231][1]=90;

        alpha[232][0]=781;
        alpha[232][1]=103;

        alpha[233][0]=787;
        alpha[233][1]=55;

        alpha[234][0]=795;
        alpha[234][1]=30;

        alpha[235][0]=798;
        alpha[235][1]=162;

        alpha[236][0]=808;
        alpha[236][1]=180;

        alpha[237][0]=813;
        alpha[237][1]=157;

        alpha[238][0]=820;
        alpha[238][1]=47;

        alpha[239][0]=835;
        alpha[239][1]=178;

        alpha[240][0]=838;
        alpha[240][1]=196;

        alpha[241][0]=853;
        alpha[241][1]=70;

        alpha[242][0]=861;
        alpha[242][1]=137;

        alpha[243][0]=863;
        alpha[243][1]=41;

        alpha[244][0]=875;
        alpha[244][1]=53;

        alpha[245][0]=878;
        alpha[245][1]=30;

        alpha[246][0]=890;
        alpha[246][1]=65;

        alpha[247][0]=899;
        alpha[247][1]=13;

        alpha[248][0]=900;
        alpha[248][1]=217;

        alpha[249][0]=914;
        alpha[249][1]=123;

        alpha[250][0]=925;
        alpha[250][1]=133;

        alpha[251][0]=931;
        alpha[251][1]=1;

        alpha[252][0]=934;
        alpha[252][1]=100;

        alpha[253][0]=936;
        alpha[253][1]=9;

        alpha[254][0]=946;
        alpha[254][1]=5;

        alpha[255][0]=953;
        alpha[255][1]=40;
}

int * genSig(int PrivKey,int m)
{
    int k,*temp,x,e,s=0;
    int n=997;
    int *P = calloc(2,sizeof(int));
    while(s==0 || x==0)
    {
    k=(rand()%(p-2))+1;
    printf("\nThe random number generated is %d\n",k);
    Pbase1[0]=1;//Deciding the base point here
    Pbase1[1]=5;
    //printf("The base point is (%d,%d)\n",Pbase[0],Pbase[1]);
    temp=genKey(PrivKey,Pbase1);
    PubKey[0]=*temp;
    PubKey[1]=*(temp+1);
    Pbase1[0]=1;//Deciding the base point here
    Pbase1[1]=5;

    printf("The base point is (%d,%d)\n",Pbase1[0],Pbase1[1]);
    temp=sclr_mult(k,Pbase1);
    x=(*temp)%n;//Same as r
    m=m%10;
    printf("r=%d\n",x);
    //printf("Private key is %d\n",PrivKey);
    Pbase1[0]=1;//Deciding the base point here
    Pbase1[1]=5;
    //printf("The base point is (%d,%d)\n",Pbase[0],Pbase[1]);
    temp=genKey(PrivKey,Pbase1);
    PubKey[0]=*temp;
    PubKey[1]=*(temp+1);
    Pbase1[0]=1;//Deciding the base point here
    Pbase1[1]=5;

    //e=(sqrt((alpha[m][0]*alpha[m][0])+(alpha[m][1]*alpha[m][1])));//Using modulus as a Hash function
    e=m;//Using message itself as hash
    e=e%n;
    printf("e=%d\n",e);
    s=(inverse1(k)*(e+(PrivKey*x)))%n;
    printf("s=%d\n",s);
    }
    P[0]=x;
    P[1]=s;
    printf("The Public Key is (%d,%d)\n",PubKey[0],PubKey[1]);
    return P;
}

int verifySig(int PubKey[2],int m,int P[2])
{
    //PAGE 105 TO SEE ALL POINTS
    int n=997;
    printf("\n\nIn Verify Function\n\n");
    printf("r=%d\n",P[0]);
    printf("s=%d\n",P[1]);
    if (P[1]>=p || P[0]>=p)
        return 0;
    else
    {
         int e,w,u1,u2,*temp;
         m=m%10;
         //e=(sqrt((alpha[m][0]*alpha[m][0])+(alpha[m][1]*alpha[m][1])));//Using modulus as a Hash function
         e=m;
         e=e%n;
         printf("e=%d\n",e);
         w=inverse1(P[1])%n;
         printf("w=%d\n",w);
         u1=(e*w)%n;
         u2=(P[0]*w)%n;
         printf("u1=%d and u2=%d\n",u1,u2);

    Pbase1[0]=1;//Deciding the base point here
    Pbase1[1]=5;
    temp=genKey(PrivKey,Pbase1);
    PubKey[0]=*temp;
    PubKey[1]=*(temp+1);
    Pbase1[0]=1;//Deciding the base point here
    Pbase1[1]=5;

        int *P1 = calloc(2,sizeof(int));
        int *P2 = calloc(2,sizeof(int));
        int *P3 = calloc(2,sizeof(int));
        printf("The base point is (%d,%d)\n",Pbase1[0],Pbase1[1]);
        temp=sclr_mult(u1,Pbase1);
        P1[0]=*temp;
        P1[1]=*(temp+1);
        //printf("The base point is (%d,%d)\n",Pbase[0],Pbase[1]);
        printf("u1*Pbase = (%d,%d)\n",P1[0],P1[1]);

    Pbase1[0]=1;//Deciding the base point here
    Pbase1[1]=5;
    temp=genKey(PrivKey,Pbase1);
    PubKey[0]=*temp;
    PubKey[1]=*(temp+1);
    Pbase1[0]=1;//Deciding the base point here
    Pbase1[1]=5;

        printf("The Public Key is (%d,%d)\n",PubKey[0],PubKey[1]);
        temp=sclr_mult(u2,PubKey);
        P2[0]=*temp;
        P2[1]=*(temp+1);
        //printf("The Public Key is (%d,%d)\n",PubKey[0],PubKey[1]);
        printf("u2*Public key = (%d,%d)\n",P2[0],P2[1]);

    Pbase1[0]=1;//Deciding the base point here
    Pbase1[1]=5;
    temp=genKey(PrivKey,Pbase1);
    PubKey[0]=*temp;
    PubKey[1]=*(temp+1);
    Pbase1[0]=1;//Deciding the base point here
    Pbase1[1]=5;

        temp=add(P1,P2);
        P3[0]=*temp;
        P3[1]=*(temp+1);
        printf("Point Generated by Addition = (%d,%d)\n",P3[0],P3[1]);

    Pbase1[0]=1;//Deciding the base point here
    Pbase1[1]=5;
    temp=genKey(PrivKey,Pbase1);
    PubKey[0]=*temp;
    PubKey[1]=*(temp+1);
    Pbase1[0]=1;//Deciding the base point here
    Pbase1[1]=5;

        if(isPAI(P3))
            return 0;
        if(P3[0]==P[0])
            return 1;
        else
            printf("\nGenerated Signature is %d. Required Value is %d\n",P3[0],P[0]);
            return 0;
    }
}
