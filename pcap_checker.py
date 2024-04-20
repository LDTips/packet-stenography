import sys

from scapy.error import Scapy_Exception
from scapy.layers.inet import UDP
from scapy.utils import rdpcap
MSG_SIZE=64

antygona = """Aby rozpocz¹æ lekturê,
kliknij na taki przycisk
który da ci pe³ny dostêp do spisu treœci ksi¹¿ki.

Jeœli chcesz po³¹czyæ siê z Portem Wydawniczym
LITERATURA.NET.PL
kliknij na logo poni¿ej.

,

ANTYGONA


PRZE£O¯Y£ KAZIMIERZ MORAWSKI



Tower Press 2000
Copyright by Tower Press, Gdañsk 2000


O s o b y d r a m a t u

Antygona, córka Edypa
Ismena, jej siostra
Chór tebañskich starców
Kreon, król Teb
Stra¿nik
Haimon, syn Kreona
Tyrezjasz, wró¿bita
Pos³aniec
Eurydyka, ¿ona Kreona


Rzecz dzieje siê przed pa³acem królewskim w Tebach.

3



[Prolog]

Antygona

O ukochana siostro ma, Ismeno!
Czy ty nie widzisz, ¿e z klêsk Edypowych
¯adnej za ¿ycia los nam nie oszczêdza?
Bo nie ma cierpieñ i nie ma ohydy,
Nie ma nies³awy i hañby, które by
Nas poœród nieszczêœæ pasma nie dotknê³y.
Có¿ bo za rozkaz znów obwieœci³ miastu
Ten, który teraz w³adzê w rêku dzier¿y?
Czyœ zas³ysza³a? Czy usz³o twej wiedzy,
¯e znów wrogowie godz¹ w naszych mi³ych?


Ismena

O Antygono, ¿adna wieœæ nie dosz³a
Do mnie, ni s³odka, ni goryczy pe³na,
Od dnia, gdy braci straci³yœmy obu,
W bratnim zabitych razem pojedynku,
Odk¹d tej nocy odesz³y Argiwów
Hufce, niczego wiêcej nie zazna³am
Ni ku pociesze, ni ku wiêkszej trosce.


Antygona

Lecz mnie wieœæ dosz³a, i dlatego z domu
Ciê wywo³a³am, by rzecz ci powierzyæ.

Ismena

Có¿ to? Ty jakieœ ciê¿kie wa¿ysz s³owa.

Antygona

O tak! Czy¿ nie wiesz, ¿e z poleg³ych braci
Kreon jednemu wrêcz odmówi³ grobu?
¯e Eteokla, jak czyniæ przystoi,
Pogrzeba³ w ziemi wœród umar³ych rzeszy,
A zaœ obwieœci³, aby Polinika
Nieszczêsne zw³oki bez czci pozosta³y,
By nikt ich p³akaæ, nikt grzeœæ siê nie wa¿y³;



Maj¹ wiêc le¿eæ bez ³ez i bez grobu,
Na pastwê ptakom ¿ar³ocznym i strawê.
S³ychaæ, ¿e Kreon czcigodny dla ciebie,
Co mówiê, dla mnie te¿ wyda³ ten ukaz
I ¿e tu przyjdzie, by tym go og³osiæ,
Co go nie znaj¹, nie na wiatr zaiste
Rzecz tê stanowi¹c, lecz gro¿¹c zarazem
Kamienowaniem ukazu przestêpcom.
Tak siê ma sprawa; teraz wraz uka¿esz,
Czyœ godn¹ rodu, czy wyrodn¹ cór¹.


Ismena

Gdy taka dola, to có¿, o nieszczêsna,
Pruj¹c czy snuj¹c bym mog³a tu przydaæ?

Antygona

Patrz, byœ wspomog³a i popar³a siostrê.

Ismena

W jakim¿e dziele? Dok¹d myœl twa mierzy?

Antygona

Ze mn¹ masz zw³oki opatrzyæ braterskie.

Ismena

Wiêc ty zamierzasz grzebaæ wbrew ukazom?

Antygona

Tak! Brata mego, a dodam... i twego;
Bo wiaro³omstwem nie myœlê siê kalaæ.

Ismena

Niczym dla ciebie wiêc zakaz Kreona?

Antygona

Niczym, on nie ma nad moimi prawa.

Ismena

Biada! O rozwa¿, siostro, jak nam ojciec
Zgin¹³ wœród sromu i poœród nies³awy,
Kiedy siê jemu b³êdy ujawni³y,
A on siê targn¹³ na w³asne swe oczy;
¯ona i matka – dwuznaczne to miano –
Splecionym wêz³em swe ¿ycie ukróca;
Wreszcie i bracia przy jednym dnia s³oñcu
Godz¹ na siebie i mordercz¹ rêk¹
Jeden drugiemu œmieræ srog¹ zadaje,
Zwa¿ wiêc, ¿e teraz i my pozosta³e
Zginiemy marnie, je¿eli wbrew prawu



Z³amiemy wolê i rozkaz tyrana.
Baczyæ to trzeba, ¿e my przecie s³abe,
Do walk z mê¿czyzn¹ niezdolne niewiasty;
¯e nam ulegaæ silniejszym nale¿y,
Tych s³uchaæ, nawet i sro¿szych rozkazów.
Ja wiêc, b³agaj¹c o wyrozumienie
Zmar³ych, ¿e muszê tak ulec przemocy,
Pos³uszna bêdê w³adcom tego œwiata,
Bo pró¿ny opór ur¹ga rozwadze.


Antygona

Ja ci nie ka¿ê niczego, ni choæbyœ
Pomóc mi chcia³a, wdziêczne by mi by³o,
Lecz stój przy swojej myœli, a ja brata
Pogrzebiê sama, potem zginê z chlub¹.
Niechaj siê zbratam z mym kochanym w œmierci
Po œwiêtej zbrodni. A d³u¿ej mi zmar³ym
Mi³¹ byæ trzeba ni¿ ziemi mieszkañcom,
Bo tam zostanê na wieki; tymczasem
Ty tu zniewa¿aj œwiête prawa bogów.

Ismena

Ja nie zniewa¿am ich, nie bêd¹c w mocy
Dzia³aæ na przekór stanowieniom w³adców.

Antygona

Rób po twej myœli; ja zaœ wnet pod¹¿ê,
By kochanemu bratu grób usypaæ.

Ismena

O ty nieszczêsna! Serce dr¿y o ciebie.

Antygona

Nie troszcz siê o mnie; nad twoim radŸ losem.

Ismena

Ale nie zdradzaj twej myœli nikomu,
Kryj twe zamiary, ja te¿ je zatajê.

Antygona

O nie! mów g³oœno, bo ciê¿kie ty kaŸnie
Œci¹gn¹æ byœ mog³a milczeniem na siebie.

Ismena

Z ¿arów twej duszy mroŸne mieciesz s³owa.

Antygona

Lecz mi³a jestem tym, o których stojê.


Ismena

Jeœli podo³asz w trudnym mar poœcigu.

Antygona

Jak nie podo³am to zaniecham dzie³a.

Ismena

Nie trza siê z góry porywaæ na mary.

Antygona

Kiedy tak mówisz, wstrêt budzisz w mym sercu
I s³usznie zmierzisz siê tak¿e zmar³emu.
Pozwól, bym ja wraz z moim zaœlepieniem
Spojrza³a w oczy grozie; bo ta groza
Chlubnej mi œmierci przenigdy nie wydrze.

Ismena

Jeœli tak mniemasz, idŸ, lecz wiedz zarazem,
¯eœ nierozwa¿na, choæ mi³ym tyœ mi³a.

Rozchodz¹ siê. Wchodzi C h ó r .

[Parodos]

Chór

O s³oñca grocie, coœ jasno znów Tebom
B³ysn¹³ po trudach i znoju,
Z³ote dnia oko, przyœwiecasz ty niebom

I w Dirki nurzasz siê zdroju.
Witaj! Tyœ sprawi³, ¿e wrogów mych krocie
W dzikim pierzchnê³y odwrocie.

Bo Polinika gniewny spór
Krwawy za¿eg³ w ziemi bój,
Z chrzêstem zapad³, z szumem piór
Œnie¿nych or³ów lotny rój
I zbroice liczne b³ys³y,
I z szyszaków pióra trys³y.


I wróg ju¿ wieñcem dzid groŸnych otoczy³
Siedmiu bram miasta gardziele,
Lecz pierzch³, nim w mojej krwi strugach siê zbroczy³,
Zanim Hefajstos ognisty w popiele

7



Pogr¹¿y³ mury, bo z ty³u nawa³em
Run¹³ na smoka Ares z wojny sza³em.

Bo Zeus nie cierpi dumnych g³ów,
A widz¹c ich wynios³y lot
I z³ota chrzêst, i pychê s³ów,
Wypuœci³ swój piorunny grot
I w zwyciêstwa samym progu.
Skarci³ butê w dumnym wrogu.

A urodzony wznak na ziemiê runie
Ten, który w namiêtnym gniewie
Miasto pogrzebaæ chcia³ w ognia ca³unie

I jak wicher d¹³ w zarzewie.
Leg³ on od Zeusa gromu powalony;
Innym znów Ares inne znaczy zgony.

Bo siedmiu – siedmiu strzeg³o wrót,
Na mê¿a m¹¿ wymierzy³ d³oñ;
Dziœ w stosach lœni za zwyciêstw trud
Ku Zeusa czci pobitych broñ.
Ale przy jednej miasta bramie
Nie b³yszczy ¿aden chwa³y ³up,
Gdzie brat na brata podniós³ ramiê,
Tam obok trupa poleg³ trup.

Wiêc teraz Nike, czci syta i s³awy,
Zwraca ku Tebom radosne swe oczy.
Po twardym znoju i po walce krwawej

Rzezi wspomnienie niech serca nie mroczy;
IdŸmy do œwi¹tyñ, a niechaj na przedzie
Teb skoczny Bakchos korowody wiedzie.

Przodownik Chóru

Lecz otó¿ widzê, jak do nas tu zd¹¿a
Kreon, co ziemi¹ t¹ w³ada;
Nowy bóstw wyrok go w myœlach pogr¹¿a,

Wa¿ne on plany wa¿y i uk³ada.
Widno, ¿e zbadaæ chcia³by nasze zdanie,
Skoro tu starców wezwa³ na zebranie.

Wchodzi K r e o n .


[Epeisodion I]

Kreon

O Tebañczycy, nareszcie bogowie
Z burzy i wstrz¹œnieñ wyrwali to miasto.
A jam was zwo³a³ tutaj przed innymi,
Boœcie wy byli podparami tronu
Za Laijosa i Edypa rz¹dów
I po Edypa zgonie m³odzieniaszkom
Pewn¹ sw¹ rad¹ s³u¿yliœcie chêtnie.
Kiedy zaœ oni za losu wyrokiem
Polegli obaj w bratobójczej walce,
Krwi¹ pokalawszy braterskie prawice,
Wtedy ja w³adzê i tron ten obj¹³em,
Który mi z prawa po zmar³ych przypada.
Trudno jest duszê przenikn¹æ cz³owieka,
Jego zamys³y i pragnienia, zanim
On ich na szczerym nie ods³oni polu.
Ja tedy w³adcê, co by rz¹dz¹c miastem,
Wnet siê najlepszych nie ima³ zamys³ów
I œmia³o woli swej nie œmia³ ujawniæ,
Za najgorszego uwa¿a³bym pana.
A gdyby wy¿ej nad dobro publiczne
K³ad³ zysk przyjació³, za nic bym go wa¿y³.
I nie milcza³bym, na Zeusa przysiêgam
Wszechwidz¹cego, gdybym spostrzeg³ zgubê
Zamiast zbawienia krocz¹c¹ ku miastu.
Nigdy te¿ wroga nie chcia³bym ojczyzny
Mieæ przyjacielem, o tym przeœwiadczony,
¯e nasze szczêœcie w szeœciu miasta le¿y
I jego dobro przyjació³ ma raiæ.
Przez te zasady podnoszê to miasto
I tym zasadom wierny obwieœci³em
Ukaz ostatni na Edypa synów:
Aby dzielnego w walce Eteokla,
Który w obronie poleg³ tego miasta,
W grobie pochowaæ i uczciæ ofiar¹,
Która w kraj zmar³ych za zacnymi idzie;
Brata zaœ jego – Polinika mniemam –
Który to bogów i ziemiê ojczyst¹
Naszed³ z wygnania i ognia po¿og¹
Zamierza³ zniszczyæ, i swoich rodaków
Krwi¹ siê napoiæ, a w pêta wzi¹æ drugich,
Wyda³em rozkaz, by chowaæ ni p³akaæ
Nikt siê nie wa¿y³, lecz zostawi³ cia³o
Przez psy i ptaki w polu poszarpane.



Taka ma wola, a nie œcierpiê nigdy,
By Ÿli w nagrodzie wyprzedzili prawych.
Kto za to miastu temu dobrze ¿yczy,
W zgonie i w ¿yciu dozna mej opieki.


Przodownik Chóru

Tak wiêc, Kreonie, raczysz rozporz¹dzaæ
Ty co do wrogów i przyjació³ grodu.
A wszelka w³adza zaprawdê ci s³u¿y
I nad zmar³ymi, i nami, co ¿yjem.


Kreon

A wiêc czuwajcie nad mymi rozkazy.

Przodownik Chóru

Poleæ m³odszemu stra¿ nad tym i pieczê.

Kreon

Przecie¿ tam stoj¹ stra¿e w pogotowiu.

Przewodnik Chóru

Czego¿ byœ tedy od nas jeszcze ¿¹da³?

Kreon

Byœcie niesfornym stanêli oporem.

Przewodnik Chóru

G³upi ten, kto by na œmieræ siê nara¿a³.

Kreon

Tak, œmieræ go czeka! Lecz wielu do zguby
Popchnê³a ¿¹dza i zysku rachuby.

Wchodzi S t r a ¿ n i k .

Stra¿nik

O najjaœniejszy, nie powiem, ¿e w biegu
Spiesz¹c ja tutaj tak siê zadysza³em;
Bom ja raz po raz przystawa³ po drodze
I chcia³em nazad zawróciæ z powrotem.
A dusza tak mi mówi³a co chwila:
Czemu¿ to, g³upi, ty karku nadstawiasz?
Czemu¿ tak lecisz? Przecie¿ mo¿e inny
Donieœæ to ksiêciu: na có¿ ty masz skomleæ?
Tak sobie myœl¹c, œpieszy³em powolnie,
A krótka droga wraz mi siê wzd³u¿a³a.
Na koniec myœlê: niech bêdzie, co bêdzie,
I stajê, ksi¹¿ê, przed tob¹, i powiem,
Choæ tak po prawdzie sam nie wiem zbyt wiele.



A zreszt¹ tuszê, ¿e nic mnie nie czeka,
Chyba, co w górze by³o mi pisane.

Kreon

Có¿ wiêc nadmiern¹ przejmuje ciê trwog¹?

Stra¿nik

Zacznê od siebie, ¿em nie zrobi³ tego,
Co siê zdarzy³o, anim widzia³ sprawcy,
¯em wiêc na ¿adn¹ nie zarobi³ karê.

Kreon

Dzielnie warujesz i wa³ujesz sprawê;
Lecz jasne, ¿e coœ przynosisz nowego.

Stra¿nik

Bo to niesporo na plac ze z³¹ wieœci¹.

Kreon

Lecz mów ju¿ w koñcu i wynoœ siê potem!

Stra¿nik

A wiêc ju¿ powiem. Trupa ktoœ co tylko
Pogrzeba³ skrycie i wyniós³ siê chy³kiem;
Rzuci³ garœæ ziemi i uczci³ to cia³o.

Kreon

Co mówisz? Któ¿ by³ tak bardzo bezczelny?

Stra¿nik

Tego ja nie wiem, bo ¿adnego znaku
Topora ani motyki nie by³o.
Ziemia woko³o by³a g³adka, zwarta,
Ani w niej stopy, ni ¿adnej kolei,
Lecz, krótko mówi¹c, sprawca znik³ bez œladu.
Skoro te¿ jeden ze stra¿y rzecz wskaza³,
Zaraz nam w myœli, ¿e w tym jakieœ licho.
Trup znik³, a le¿a³ nie pod grub¹ zasp¹,
Lecz przyprószony, jak czyni¹, co winy
Siê wobec zmar³ych strachaj¹; i zwierza
Lub psów szarpi¹cych trupy ani œladu.
Wiêc zacz¹³ jeden wyrzekaæ na drugich,
Jeden drugiego winowaæ, i by³o
Blisko ju¿ bójki, bo któ¿ by ich zgodzi³?
W ka¿dym ze stra¿y wietrzyliœmy sprawcê,
Lecz tak na oœlep, bo nikt siê nie przyzna³.
I my gotowi i ¿ary braæ w rêce,
I w ogieñ skoczyæ, i przysi¹c na bogów,
¯e nie my winni ani byli w spó³ce



Z tym, co obmyœli³ tê rzecz i wykona³.
Wiêc koniec koñcem, gdy dalej tak nie sz³o,
Jeden rzek³ s³owo, które wszystkim oczy
Zary³o w ziemiê; boœmy nie widzieli,
Co na to odrzec, a strach nas zdj¹³ wielki,
Co z tego bêdzie. Rzek³ wiêc na ten sposób,
¯e tobie wszystko to donieœæ nale¿y.
I tak siê stanê³o, a mnie nieszczêsnemu
Los kaza³ za¿yæ tej przyjemnej s³u¿by.
Wiêc po niewoli sobie i wam stajê,
Bo nikt nie lubi z³ych nowin zwiastuna.


Przodownik Chóru

O panie, mnie ju¿ od dawna siê roi,
¯e siê bez bogów przy tym nie obesz³o.

Kreon

Milcz, jeœli nie chcesz wzbudziæ mego gniewu
I prócz staroci ukazaæ g³upoty!
Bo brednie pleciesz, mówi¹c, ¿e bogowie
O tego trupa na ziemi siê troszcz¹.
Czy¿by z szacunku, jako dobroczyñcê,
Jego pogrzebali, jego, co tu wtargn¹³,
Aby œwi¹tynie i ofiarne dary
Zburzyæ, spustoszyæ ich ziemiê i prawa?
Czy wed³ug ciebie bóstwa czcz¹ zbrodniarzy?
O nie, przenigdy! Lecz tego tu miasta
Ludzie ju¿ dawno, przeciw mnie szemraj¹c,
G³ow¹ wstrz¹sali i jarzmem ukrycie
Przeciw mym rz¹dom i mojej osobie.
Wiem ja to dobrze, ¿e za ich pieni¹dze
Stra¿e siê tego dopuœci³y czynu.
Bo nie ma gorszej dla ludzi potêgi,
Jak pieni¹dz: on to i miasta rozburza,
On to wypiera ze zagród i domu,
On prawe dusze krzywi i popycha
Do szpetnych kroków i nieprawych czynów.
Zbrodni on wszelkiej ludzkoœci jest mistrzem
I drogowskazem we wszelkiej sromocie.
A ci, co czyn ten za pieni¹dz spe³nili,
Dopiêli swego: spadn¹ na nich kaŸnie.
Bo jako Zeusa czczê i ho³d mu sk³adam
– Miarkuj to dobrze, a klnê siê przysiêg¹ –
Tak jeœli zaraz schwytanego sprawcy
Nie dostawicie przed moje oblicze,
To jednej œmierci nie bêdzie wam dosyæ,
Lecz wprzódy wisz¹c bêdziecie zeznawaæ,
Byœcie w przysz³oœci wiedzieli, sk¹d grabiæ
I ci¹gn¹æ zyski, i mieli naukê,



¯e nie na wszelki zysk godziæ nale¿y.
Bo to jest pewne, ¿e brudne dorobki
Czêœciej do zguby prowadz¹ ni¿ szczêœcia.

Stra¿nik

Wolno¿ mi mówiæ? Czy pójœæ mam w milczeniu?

Kreon

Czy¿ nie wiesz jeszcze, jak g³os twój mi wstrêtny?

Stra¿nik

Uszy ci rani czy te¿ duszê twoj¹?

Kreon

Có¿ to? Chcesz badaæ, sk¹d id¹ me gniewy?

Stra¿nik

Sprawca ci duszê, a ja uszy trapiê.

Kreon

Có¿ to za urwisz z niego jest wierutny!

Stra¿nik

A przecie¿ nie ja czyn ten pope³ni³em.

Kreon

Ty! – swoj¹ dusz¹ frymarcz¹c w dodatku.

Stra¿nik

O nie!
Pró¿ne to myœli, pró¿niejsze domys³y.


Kreon

Zmyœlne twe s³owa, lecz je¿eli winnych
Mi nie stawicie, to wnet wam zawita,
¯e brudne zyski prowadz¹ kaŸnie.

Stra¿nik

O, niech go ujm¹, owszem, lecz cokolwiek
Teraz siê stanie za dopustem losu,
Ty mnie ju¿ tutaj nie zobaczysz wiêcej;
Bo ju¿ i teraz dziêkujê ja bogom,
¯em wbrew nadziei st¹d wyszed³ bez szwanku.


Odchodzi. K r e o n wchodzi do pa³acu.

13



[Stasimon I]

Chór

Si³a jest dziwów, lecz nad wszystkie siêga
Dziwy cz³owieka potêga.
Bo on prze œmia³o poza sine morze,
Gdy toñ siê wzdyma i k³êbi,
I z roku na rok swym lemieszem porze
Matkê ziemicê do g³êbi.

Lotny ród ptaków i stepu zwierzêta,
I dzieci fali usidla on w pêta,

Wszystko rozumem zwyciê¿y.
Dzikiego zwierza z gór œci¹gnie na b³onie,
Krn¹brny kark tura i grzywiaste konie

Ujarzmi³ w swojej uprzê¿y.

Wynalaz³ mowê i myœli da³ skrzyd³a,
I ¿ycie uj¹³ w porz¹dku prawid³a,
Od mroŸnych wichrów na deszcze i gromy
Zbudowa³ sobie schroniska i domy,


Na wszystko z rad¹ on gotów.
Lecz choæby œmia³o patrza³ w wiek daleki,
Choæ ma na bóle i cierpienia leki,

Œmierci nie ujdzie on grotów.

A si³ potêgê, które w duszy tlej¹,
Popchnie on zbrodni lub cnoty kolej¹;
Je¿eli prawa i bogów czeœæ wyzna,

To ho³d mu odda ojczyzna;
A bêdzie jej wrogiem ten, który nie z bogiem
Na czeœæ i prawoœæ siê ciska;
Niechajby on sromu mi nie wniós³ do domu,
Nie skala³ mego ogniska!

Przodownik Chóru

Lecz jaki¿ widok uderza me oczy?
Czy¿ ja zdo³a³bym wbrew prawdzie zaprzeczyæ,
¯e to dzieweczka idzie Antygona?
O ty nieszczêsna, równie nieszczêsnego
Edypa córo!
Có¿¿e siê sta³o? Czy ciê na przestêpstwie
Ukazu króla schwytano i teraz
Wskutek tej zbrodni prowadz¹ jak brankê?


Wchodzi S t r a ¿ n i k prowadz¹c A n t y g o n ê .

14



[Epeisodion II]

Stra¿nik

Oto jest dziewka, co to pope³ni³a.
Tê schwytaliœmy. Lecz gdzie¿ jest Kreon?

Wchodzi K r e o n .

Przodownik Chóru

Wychodzi oto z domu w sam¹ porê.

Kreon

Có¿ to? Jakie¿ tu zaszed³em zdarzenie?

Stra¿nik

Niczego, panie, nie trza siê odrzekaæ,
Bo myœl póŸniejsza k³am zada zamys³om.
Ja bo dopiero kl¹³em, ¿e ju¿ nigdy
Nie stanê tutaj po groŸbach, coœ miota³;
Ale ta nowa, wielka niespodzianka
Nie da siê zmierzyæ z nijak¹ radoœci¹.
Idê wiêc, chocia¿ tak siê zaklina³em,
Wiod¹c tê dziewkê, któr¹ przychwytano,
Gdy grób g³adzi³a; ¿aden los tym razem
Mnie tu nie przywiód³, lecz w³asne odkrycie.
S¹dŸ j¹ i badaj; jam sobie zas³u¿y³,
Bym z tych opa³ów wydosta³ siê wreszcie.


Kreon

Jakim sposobem i gdzieœ j¹ schwyta³?

Stra¿nik

Trupa pogrzeba³a. W dwóch s³owach masz wszystko.

Kreon

Czy pewny jesteœ tego, co tu g³osisz?

Stra¿nik

Na w³asne oczy przecie¿ j¹ widzia³em
Grzebi¹c¹ trupa; chyba jasno mówiê.

Kreon

Wiêc na gor¹cym zaszed³eœ j¹ uczynku?

Stra¿nik

Tak siê rzecz mia³a: kiedyœmy tam przyszli,
GroŸbami twymi srodze przep³oszeni,

15



Zmietliœmy z trupa ziemiê i znów, nagie
I ju¿ nadpsute zostawiwszy cia³o,
Na bliskim wzgórzu siedliœmy, to bacz¹c,
By nam wiatr nie niós³ wstrêtnego zaduchu.
A jeden beszta³ drugiego s³owami,
By siê nie leniæ i nie zaspaæ sprawy.
To trwa³o chwilê; a potem na niebie
Zab³ysn¹³ w œrodku ognisty kr¹g s³oñca
I grzaæ poczê³o; a¿ nagle siê z ziemi
Wicher poderwa³ i wœród strasznej tr¹by
Wy³ po równinie, dr¹c liœcie i korê
Z drzew, i zape³ni³ kurzaw¹ powietrze;
Przymkn¹wszy oczy, dr¿eliœmy ze strachu.
A kiedy wreszcie ten szturm siê uciszy³,
Widzimy dziewkê, która tak boleœnie
Jak ptak zawodzi, gdy znajdzie swe gniazdo
Obrane z piskl¹t i opustosza³e.
Tak ona, trupa dojrzawszy nagiego,
Zaczyna jêczeæ i przekleñstwa miotaæ
Na tych, co brata obna¿yli cia³o.
I wnet przynosi garœæ suchego piasku,
A potem z wiadra, co dŸwiga na g³owie,
Potrójnym p³ynem martwe skrapia zw³oki.
My wiêc rzucimy siê na ni¹ i dziewkê
Chwytamy, ona zaœ nic siê nie lêka.
Badamy dawne i œwie¿e jej winy,
Ona zaœ¿adnej nie zaprzecza zbrodni;
Co dla mnie mi³e, lecz i przykre by³o,
Bo ¿e z opa³ów sam siê wydosta³em,
By³o mi s³odkie, lecz ¿em w nie pogr¹¿y³
Znajomych, przykre. Chocia¿ statecznie,
Skorom ja ca³y, resztê lekko wa¿ê.


Kreon

Lecz ty, co g³owê tak sk³aniasz ku ziemi,
Mów, czy to prawda, czy donos k³amliwy?

Antygona

Jam to spe³ni³a, zaprzeczaæ nie myœlê.

Kreon

Do S t r a ¿ n i k a

Ty wiêc siê wynoœ, gdzie ci siê podoba,
Wolny od winy i ciê¿kich podejrzeñ.

S t r a ¿ n i k odchodzi.

A ty powiedz mi teraz w dwóch s³owach,
Czy¿eœ wiedzia³a o moim zakazie?


Antygona

Wiedzia³am dobrze. Wszak¿e nie by³ tajny.

Kreon

I œmia³aœ wbrew tym stanowieniom dzia³aæ?

Antygona

Nie Zeus to przecie¿ obwieœci³ to prawo
Ni wola Diki, podziemnych bóstw siostry,
Tak¹ ród ludzki zwi¹za³a ustaw¹.
A nie mniema³am, by ukaz twój ostry
Tyle mia³ wagi i si³y w cz³owieku,
Aby móg³³amaæœwiête prawa bo¿e,
Które s¹ wieczne i trwaj¹ od wieku,
¯e ich pocz¹tku nikt zbadaæ nie mo¿e.
Ja wiêc nie chcia³am ulêkn¹æ siê cz³eka
I za z³amanie praw tych kiedyœ bogom
Zdawaæ tam sprawê. Bom œmierci ja pewna
Nawet bez twego ukazu; a jeœli
Wczeœniej œmieræ przyjdzie, za zysk to poczytam.
Bo komu przysz³o ¿yæ wœród nieszczêœæ tylu,
Jak¿eby w œmierci zysku nie dopatrzy³?
Tak wiêc nie mierzi mnie œmierci ta groŸba,
Lecz mierzi³oby mnie braterskie cia³o
Nie pogrzebane. Tak, œmieræ mnie ni straszy;
A jeœli g³upio dzia³aæ ci siê zdajê,
Niech mój nierozum za nierozum staje.


Przodownik Chóru

Krn¹brne po krn¹brnym dziewczyna ma ojcu
Obejœcie, grozie nie ust¹pi ³atwo.

Kreon

Lecz wiedz, ¿e czêsto zamys³y zbyt harde
Spadaj¹ nisko, ¿e czêsto siê widzi,
Jako ¿elazo najtwardsze wœród ognia
Gnie siê i mimo swej twardoœci pêka;
Wiem te¿, ¿e drobne wêdzid³o rumaki
Dzikie poskramia. Bo tym nieprzystojna
Wynios³oœæ, którzy u innych w niewoli.
Dziewka ta jedn¹ splami³a siê win¹
Rozkazy dane obchodz¹c i ³ami¹c,
Teraz przed drugim nie sroma siê gwa³tem,
Z czynu siê che³pi i nadto ur¹ga.
Lecz nie ja mê¿em, lecz ona by by³a,
Gdyby postêpek ten jej uszed³ p³azem.
Ale czy z siostry, czy choæby i bli¿szej
Krwi¹ mi istoty ona pochodzi³a,
Ona i siostra nie ujd¹ przenigdy


17



Œmierci straszliwej; bo i siostrê skarcê,
¯e jej spólniczk¹ by³a w tym pogrzebie.
Wo³aæ mi tamt¹, któr¹ co dopiero
Widzia³em w domu zmieszan¹, szalon¹.
Tak duch zazwyczaj tych zdradza, co tajnie
Siê dopuœcili jakiegoœ wystêpku.
Wstrêt zaœ ja czujê przeciw tym z³oczyñcom,
Którzy swe grzechy chc¹ potem upiêkszaæ.


Antygona

Chceszli co wiêcej, czyli œmieræ mi zdaæ?

Kreon

O nie! w tym jednym zawiera siê wszystko.

Antygona

Wiêc na có¿ zwlekaæ? Jako twoje s³owa
Mier¿¹ i oby zawsze mnie mierzi³y,
Tak wstrêtne tobie wszystkie me postêpki.
A jednak sk¹d bym piêkniejsz¹ ja s³awê
Uszczknê³a, jako z brata pogrzebania?
I ci tu wszyscy rzecz by pochwalili,
Gdyby im trwoga nie zawar³a mowy.
Ale tyranów los ze wszech miar b³ogi,
Wolno im czyniæ, co zechc¹, i mówiæ.


Kreon

Sama tak s¹dzisz poœród Kadmejczyków.

Antygona

I ci tak s¹dz¹, lecz stulaj¹ wargi.

Kreon

Nie wstyd ci, jeœli od tych siê wyró¿nia¿?

Antygona

Czciæ swe rodzeñstwo nie przynosi wstydu.

Kreon

Nie by³ ci bratem ten, co poleg³ drugi?

Antygona

Z jednego ojca i matki zrodzony.

Kreon

Czemu¿ wiêc niesiesz czeœæ, co jemu wstrêtna?

Antygona

Zmar³y nie rzuci mi skargi tej w oczy.


Kreon

Jeœli na równi z nim uczcisz z³oczyñcê?

Antygona

Nie jak niewolnik, lecz jak brat on zgin¹³.

Kreon

On, co pustoszy³ kraj, gdy tamten broni³?

Antygona

A jednak Hades po¿¹da praw równych.

Kreon

Dzielnemu równoœæ ze z³ym nie przystoi.

Antygona

Któ¿ wie, czy takie wœród zmar³ych s¹ prawa?

Kreon

Wróg i po œmierci nie stanie siê mi³ym.

Antygona

Wspó³kochaæ przysz³am, nie wspó³nienawidziæ.

Kreon

Jeœli chcesz kochaæ, kochaj i w Hadesie.
U mnie nie bêdzie przewodziæ kobieta.

Przodownik Chóru

Lecz otó¿ wiod¹ Ismenê, o panie;
Widaæ jej boleœæ i s³ychaæ jej ³kanie,
A jakaœ chmura przes³ania jej oczy
I piêkn¹ dziewki twarz mroczy.

Kreon

O ty, co w domu przypiê³aœ siê do mnie
Jak w¹¿ podstêpnie, ¿em wiedzieæ wrêcz nie móg³,
I¿ na m¹ zgubê dwa wyrodki ¿ywiê –
Nu¿e, mów teraz, czyœ by³a wspólniczk¹
W tym pogrzebaniu, lub wyprzej siê winy.


Ismena

Winna ja jestem, jak stwierdzi to siostra,
I biorê na siê tej zbrodni po³owê.

Antygona

Lecz sprawiedliwoœæ przeczy twym twierdzeniom;
Aniœ ty chcia³a, ni jaæ przypuœci³am.

19



Ismena

Jednak w niedoli twojej nie omieszkam
Wzi¹æ na siê cz¹stkê twych cierpieñ i kaŸni.

Antygona

Hades i zmarli wiedz¹, kto to zdzia³a³.
S³owami œwiadczyæ mi³oœæ, to nie mi³oœæ.

Ismena

O, nie zabraniaj mi siostro, choæ w œmierci
Z tob¹ siê z³¹czyæ i uczciæ zmar³ego.

Antygona

Nie chcê twej œmierci ani zwij twym dzie³em,
Coœ nie sprawi³a; mój zgon starczy bratu.

Ismena

Lecz jaki¿¿ywot mnie czeka bez ciebie?

Antygona

Pytaj Kreona! Zwyk³aœ nañ ty baczyæ.

Ismena

Po có¿ mnie drêczysz bez ¿adnej potrzeby?

Antygona

Cierpiê ja, ¿e mi œmiaæ przysz³o siê z ciebie.

Ismena

W czym bym choæ teraz ci przydaæ siê mog³a?

Antygona

Myœl o ratunku, ja go nie zawiszczê.

Ismena

O, ja nieszczêsna! Wiêc chcesz mnie porzuciæ?

Antygona

Wybra³aœ¿ycie – ja ¿ycia ofiar¹.

Ismena

Sk¹d wiesz, co na dnie s³ów moich siê kryje?

Antygona

W s³owach ty rady, ja szuka³am w czynie.

Ismena

A jednak wina ta sama nas ³¹czy.


Antygona

B¹dŸ zdrowa, ¿yjesz – a moja ju¿ dusza
W krainie œmierci... zmar³ym œwiadczyæ mo¿e.


Kreon

Z dziewcz¹t siê jednej teraz zwichn¹³ rozum,
Druga od m³odu wci¹¿ by³a szalona.

Ismena

O w³adco, w ludziach zgnêbionych nieszczêœciem
Umys³ siê chwieje pod ciosów obuchem.

Kreon

W tobie zaiste, co ³¹czysz siê z zbrodni¹.

Ismena

Bo có¿ mi ¿ycie warte bez mej siostry?

Kreon

Jej nie nazywaj – bo ona ju¿ zmar³a.

Ismena

Wiêc narzeczon¹ chcesz zabiæ ty syna?

Kreon

S¹ inne ³any dla jego posiewu.

Ismena

Lecz on by³ dziwnie do niej dostrojony.

Kreon

Z³ymi dla synów niewiasty siê brzydzê.

Ismena

Drogi Haimonie, jak ojciec ciê krzywdzi!

Kreon

Twój g³os i swadŸby zbyt mier¿¹ mnie twoje.

Przodownik Chóru

A wiêc chcesz wydrzeæ kochankê synowi?

Kreon

Hades pos³aniem bêdzie tej mi³oœci.

Przodownik Chóru

Taka wiêc wola, ¿e ta umrzeæ musi?

21



Kreon

Moja i twoja; lecz dosyæ tych zwlekañ!
WiedŸcie je, s³ugi, w dom, bo odt¹d maj¹
¯yæ jak niewiasty, nie wed³ug swej woli.
Toæ i zbyt œmia³e ulêkn¹ siê serca,
Gdy widmo œmierci zagl¹dnie im w oczy.


Stra¿ odprowadza do pa³acu A n t y g o n ê i I s m e n ê .

[Stasimon II]

Chór

Szczêœliwy, kogo w ¿yciu klêski nie dosiêg³y!

Bo skoro bóg potrz¹œnie domowymi wêg³y,
Z jednego gromu ca³y szereg nieci,
Po ojcach godzi i w dzieci.

Tak jako fale na morzu siê piêtrz¹,
Gdy wicher tracki do g³êbiny wpadnie
I ryje i³y drzemi¹ce gdzieœ na dnie,
A¿ brze¿ne ska³y od burzy zajêcz¹ –

Tak ju¿ od wieków w Labdakidów domy

Po dawnych gromach nowe godz¹ gromy;
Bóle minionych pokoleñ
Nie nios¹ ulg i wyzwoleñ.

I ledwie s³oñce promienie rozpostrze
Ponad ostatni¹ odnog¹ rodzeñstwa,
A ju¿ bóstw krwawych podcina j¹ ostrze,


Ob³êd i sza³u przekleñstwa.

O Zeusie, któ¿ siê z tw¹ potêg¹ zmierzy?
Ciebie ni czasu odwieczne miesi¹ce,
Ni sen nie zmo¿e wœród swoich obierzy.
Ty, co Olimpu szczyty jaœniej¹ce


Przez wieki dzier¿ysz promienny,

Równy w swej sile, niezmienny.
A wieczne prawo gniecie ziemi syny,
¯e nikt ¿ywota nie przejdzie bez winy.

Nadzieja z³udna, bo jednym na skrzyd³a,
Drugim omota w swe sid³a;
¯¹dz lotnych wzbudzi w nich ognie,
A¿¿ycie pióra te pognie.

22



A wieczn¹ prawd¹, ¿e w przystêpie dumy
Mieni¹ dobrymi ci nieprawe czyny,
Którym bóg zmiesza³ rozumy!
Nikt siê na ziemi nie ustrze¿e winy.

Przodownik Chóru

Lecz otó¿ Haimon, z twojego potomstwa
wiekiem najm³odszy; widocznie boleje
Nad ciê¿kim, losem swej umi³owanej

I po swym szczêœciu ³zy leje.

Wchodzi H a i m o n .

[Epeisodion III]

Kreon

Wkrótce przejrzymy jaœniej od wró¿bitów.
O synu! Czy ty przybywasz tu gniewny
Wskutek wyroku na tw¹ narzeczon¹,
Czy w ka¿dej doli zachowasz mnie mi³oœæ?


Haimon

Twoim ja, ojcze! Skoro m¹drze radzisz,
Idê ja chêtnie za twoim przewodem;
I ¿aden zwi¹zek nie bêdzie mi dro¿szy
Ponad wskazówki z ust twoich rozumnych.


Kreon

O! tak, mój synu, byæ zawsze powinno:
Zdanie ojcowskie ponad wszystkim wa¿yæ,
Przecie¿ dlatego b³agaj¹ ojcowie,
Aby powolnych synów dom ich chowa³,
A równo z ojcem uczcili przyjació³.
Kto by zaœ p³odzi³ potomstwo nie warte,
Có¿ by on chowa³, jak troski dla siebie,
A wobec wrogów wstyd i poœmiewisko?
Synu, nie folguj wiêc ¿¹dzy, nie porzuæ
Dla marnej dziewki rozs¹dku! Wiedz dobrze,
¯e nie ma bardziej mroŸnego uœcisku,
Jak w z³ej kobiety ramionach, bo trudno
O wiêksz¹ klêskê jako z³y przyjaciel.
Przeto ze wstrêtem ty porzuæ tê dziewkê,
Aby w Hadesie innemu siê da³a.



Bo skorom pozna³, ¿e z ca³ego miasta
Ona jedyna opar³a siê prawu,
Nie myœlê stan¹æ wszem wobec jak k³amca.
Ale j¹ stracê. Rodzinnego Zeusa
Niech sobie wzywa! Jeœli wœród rodziny
Nie bêdzie ³adu, jak obcych poskromiæ?
Bo kto w swym domu potrafi siê rz¹dziæ,
Ten sterem pañstwa pokieruje dobrze;
Kto zaœ zuchwale przeciw prawu dzia³a
I tym, co rz¹dz¹, narzucaæ chce wolê,
Ten nie doczeka siê mego uznania.
Wybrañcom ludu pos³usznym byæ trzeba
W dobrych i s³usznych – nawet w innych sprawach.
Takiego mê¿a rz¹dom bym zaufa³,
Po takim s³u¿by wygl¹da³ ochotnej,
Taki by w starciu oszczepów i w walce
Wytrwa³ na miejscu jak dzielny towarzysz.
Nie ma zaœ wiêkszej klêski od nierz¹du:
On gubi miasta, on domy rozburza,
On wœród szeregów roznieca ucieczkê.
Zaœ poœród mê¿ów powolnych rozkazom
Za ¿ycia puklerz stanie pos³uszeñstwo.
Tak wiêc wypada strzec prawa i w³adzy
I nie ulegaæ niewiast samowoli.
Je¿eli upaœæ, to z rêki paœæ mêskiej,
Bo hañba doznaæ od niewiasty klêski.


Przodownik Chóru

Nam, jeœli staroœæ rozumu nie t³umi,
Zdajesz siê mówiæ o tym bardzo trafnie.

Haimon

Ojcze, najwy¿szym darem ³aski bogów
Jest niew¹tpliwie u cz³owieka rozum.
A ja s³usznoœci twoich s³ów zaprzeczyæ
Ani bym umia³, ani chcia³bym zdo³aæ.
Ale s¹d zdrowy móg³by mieæ te¿ inny.
Mam ja tê wy¿szoœæ nad tob¹, ¿e mogê
Poznaæ, co ludzie mówi¹, czyni¹, gani¹,
Bo na twój widok zdejmuje ich trwoga
I s³owo, ciebie ra¿¹ce, zamiera.
A wiêc cichaczem posz³o mi wys³uchaæ,
Jak miasto nad t¹ siê¿ali dziewic¹,
¯e ze wszech niewiast najmniej ona winna,
Po najzacniejszym czynie marnie koñczy,
Czy¿ bo ta, co w swym nie przenios³a sercu,
By brat jej le¿a³ martwy bez pogrzebu,
Psom na po¿arcie i ptactwu dzikiemu,
Raczej nagrody nie godna jest z³otej?


24



Takie siê g³osy odzywaj¹ z cicha.
Ja zaœ, o ojcze, niczego nie pragnê,
Jak by siê tobie dobrze powodzi³o.
Bo jeœli wiêkszy skarb nad dobre imiê
Ojca dla dzieci lub dzieci dla ojca?
Nie ¿yw wiêc tego, ojcze, przeœwiadczenia,
¯e tylko twoje coœ warte jest zdanie;
Bo kto jedynie sam sobie zawierzy,
Na swojej mowie polega i duszy,
Gdy go ods³oni¹, pustym siê oka¿e.
Choæby by³ m¹dry, przystoi mê¿owi
Ci¹gle siê uczyæ, a niezbyt upieraæ.
Widzisz przy rw¹cych strumieniach, jak drzewo,
Które siê nagnie, zachowa konary,
A zbyt oporne – z korzeniami runie.
Tak¿e i ¿eglarz, który zbyt naci¹gnie
¯agle i folgi nie daje, przewróci
£ódŸ i osi¹dzie bez ³awie na desce.
Ust¹p ty przeto i zaniechaj gniewu,
Bo jeœli wolno s¹dziæ mnie, m³odszemu,
Mniemam, ¿e taki cz³owiek najprzedniejszy,
Który op³ywa w rozum z przyrodzenia;
Jeœli tak nie jest – a i to siê zdarzy –
Niechaj rad dobrych zbyt lekko nie wa¿y.


Przodownik Chóru

O, panie, s³uchaj, jeœli w porê mówi,
A ty znów ojca; obaj m¹drze mówi¹.

Kreon

A wiêc w mym wieku mam m¹droœci szukaæ
I braæ nauki u tego m³okosa?

Haimon

Nauki s³uszne; a jeœli ja m³ody,
To na rzecz raczej, ni¿ wiek, baczyæ trzeba.


Kreon

Ba rzecz, niesfornym która czeœæ oddaje?

Haimon

Ni s³owem œmia³bym czeœæ tak¹ zalecaæ.

Kreon

A czy¿ nie w taki b³¹d popad³a tamta?

Haimon

Przeczy g³os ludu, co mieszka w Teb grodzie.

25



Kreon

Wiêc lud mi wska¿e, co ja mam zarz¹dzaæ?

Haimon

Niemal jak m³odzian porywczy przemawiasz.

Kreon

Sobie czy innym gwoli ja tu rz¹dzê?

Haimon

Marne to pañstwo, co li panu s³u¿y.

Kreon

Czy¿ nie do w³adcy wiêc pañstwo nale¿y?

Haimon

Piêknie byœ wtedy rz¹dzi³... na pustyni.

Kreon

Ten, jak siê zdaje, z tamt¹ dziewk¹ trzyma.

Haimon

Jeœli ty dziewk¹: o ciebie siê troskam.

Kreon

Z ojcem siê swarz¹c, o przewrotny synu?

Haimon

Bo widzê, ¿e ty z drogi zbaczasz prawej.

Kreon

B³¹dzê¿ ja strzeg¹c godnoœci mej w³adzy?

Haimon

Nie strze¿esz – w³adz¹ pomiataj¹c bogów.

Kreon

O niski duchu, na s³u¿bie kobiety!

Haimon

Lecz w s³u¿bie z³ego nie znajdziesz mnie nigdy.

Kreon

Ca³a twa mowa jej sprawy ma broniæ.

Haimon

Twej sprawy, mojej i podziemnych bogów.


Kreon

Nigdy ju¿¿ywej ty jej nie poœlubisz.

Haimon

Zginie – to œmierci¹ sprowadzi zgon inny.

Kreon

A wiêc ju¿ groŸb¹œmiesz we mnie ty godziæ?

Haimon

Nie godzê: zwalczyæ puste chcê zamys³y.

Kreon

Wnet po¿a³ujesz twych nauk, m³okosie!

Haimon

Nie by³byœ ojcem, rzek³bym, ¿eœ niem¹dry.

Kreon

Niewiast s³u¿alcze, przestañ siê uprzykrzaæ!

Haimon

Chcesz wiêc ty mówiæ, a drugich nie s³uchaæ?

Kreon

Doprawdy? Ale, na Olimp, wiedz o tym,
¯e ciê twe drwiny o zgubê przyprawi¹.
WiedŸcie tu dziewkê; niechaj¿e wyrodna
W oczach kochanka tu ginie, natychmiast!

Haimon

Nie umrze ona przy mnie! Nie marz o tym!
Nie ujrzê tego, raczej ty nie ujrzysz
Wiêcej mojego oblicza, je¿eli
W szale na bliskich porywaæ siê myœlisz.


Odchodzi.

Przodownik Chóru

Jak to? Czy¿ obie ty zg³adziæ zamyœlasz?

Kreon

Niewinna ujdzie; s³usznie mnie strofujesz.

Przodownik Chóru

A jaki¿ tamtej gotujesz ty koniec?

Kreon

Gdzieœ na bezludnym zamknê j¹ pustkowiu,


W skalistym lochu zostawiê¿yj¹c¹,
Strawy przydaj¹c jej tyle, by kaŸniê
Pozbawiæ grozy i kl¹twy nie œci¹gaæ;
A tam jej Hades, którego jedynie
Z bogów uwielbia, mo¿e da zbawienie –
Lub pozna wreszcie, jeœli marnie zginie,
¯e pró¿n¹ s³u¿b¹ czciæ Hadesu cienie.


Odchodzi do pa³acu.

[Stasimon III]

Chór

Mi³oœci, któ¿ siê wyrwie z twych obierzy!
Mi³oœci, która runiesz na ofiary,
W g³adkich dziew licach gdy rozniecisz czary.
Kroczysz po morzu i wœród chat pasterzy,
Ni bóg nie ujdzie przed twoim nawa³em,
Ani œmiertelny. Kim w³adasz, wre sza³em.


Za twym podmuchem – do winy
Zboczy i prawy wraz cz³owiek;
Spory ty szerzysz wœród jednej rodziny.
Urok wystrzela zwyciêsko spod powiek
Dziewicy, siêgnie i praw majestatu
Moc Afrodyty, co przewodzi œwiatu.


Przodownik Chóru

A i ja nawet, chocia¿ wiernie s³u¿ê,
Prawie siê w duszy na ukazy burzê,

A boleœæ serce mi rani;
Bo straszny widok uderza me oczy:
Do wszechch³on¹cej Antygona kroczy

Ciemnej hadesu przystani.

Stra¿ prowadzi A n t y g o n ê .


[Epeisodion IV]

Antygona

Patrzcie, o patrzcie, wy, ziemi tej dzieci,
Na mnie, krocz¹c¹ w smutne œmierci cienie,
Ogl¹daj¹c¹ ostatnie promienie
S³oñca, co nigdy ju¿ mi nie zaœwieci;
Bo mnie Hadesa dziœ rêka œmiertelna
Do Acherontu bladych wiedzie w³oœci.


Ani zazna³am mi³oœci,
Ani mi zabrzmi ¿adna pieœñ weselna;
Ale na zimne Acherontu ³o¿e

Cia³o nieszczêsne me z³o¿ê.

Chór

Pieœni ty godna i w chwa³y rozkwicie
W kraj œmierci niesiesz twe ¿ycie.
Ani ciê chorób przygnêbi³o brzemiê,
Ni miecza ostrze zwali³o na ziemiê,
Lecz w³asnowolna, nie dobieg³szy kresu,


¯ywa w kraj st¹pasz hadesu.

Antygona

S³ysza³am niegdyœ o frygijskiej Niobie,
Córce Tantala, i jej strasznym zgonie,
¯e skamienia³a w swej niemej ¿a³obie
I odt¹d ci¹gle we ³zach bólu tonie.
Ska³a owi³a j¹, jak bujne bluszcze,
A na jej szczytach œnieg miecie, deszcz pluszcze,


Rozpaczy ³kaniem zroszone jej ³ono –
Mnie te¿ kamienn¹ poœciel przeznaczono.

Chór

Lecz ona przecie¿ z krwi bogów jest rodem,
My œmiertelnego pokolenia p³odem.
Ho³d jednak temu, kto choæ w œmierci progu


Dorówna bogu.

Antygona

Ur¹gasz biednej. Czemu¿ obel¿yw¹
Mow¹ mnie ranisz, pókim jeszcze ¿yw¹?
Miasto i mê¿e dzier¿¹cy te grody,
Wzywam was, zwróæcie litosne swe oczy,
I wy, Teb gaje i dirkejskie wody,
Na mnie, co idê ku ciemnej pomroczy,
Nie op³akana przez przyjació³¿ale,
Do niezwyk³ego grobowca gdzieœ w skale.


29



O, ja nieszczêsna!
Anim ja zmar³a, ani te¿ przy ¿yciu;
Œmieræ mnie ju¿ trzyma w swym mroŸnym spowiciu.

Chór

W nadmiarze pychy zuchwa³ej
Z tronem siê Diki twe myœli i mowy
Zderzy³y w locie, z³ama³y.
Z³y duch ciêœciga rodowy.

Antygona

Mowa ta g³êbi¹ mego serca targa;
Dotkn¹³eœ ojca ty sromu
I ws³owach twoich rozbrzmia³a znów skarga

Nad nieszczêœciami Labdakidów domu.
Straszn¹ ja pomnê³o¿nicê,
W której syn z matk¹ zdro¿ne œluby wi¹¿e.

Nieszczêœni moi rodzice!
Kl¹tw¹ brzmienia dziœ do was pod¹¿ê,
Dziewiczoœæ nios¹c wam serca.
O drogi bracie, z³owrogie twe œluby
By³y pocz¹tkiem pogromu i zguby;
Tyœ – choæ zmar³y – mój morderca.

Chór

Zmar³ych czciæ – czcigodny czyn,
Ale godny kaŸni b³¹d –
£amaæ prawo, waliæ rz¹d.
Tyœ zginê³a z w³asnych win.

Antygona

Bez ³ez, przyjació³, weselnego pienia
Kroczê ju¿, biedna, ku œmiertelnej toni.
Wnet ju¿ nie ujrzê ni s³oñca promienia,
Nikt ³zy nad moj¹ dol¹ nie uroni.

Wchodzi K r e o n .

Kreon

Czy¿by kto usta³ w przedzgonnych tych skargach,
Gdyby mu dano siê¿aliæ bez koñca?
Bierzcie st¹d dziewkê i w ciemnym j¹ grobie
Zawrzyjcie zaraz, jak ju¿ nakaza³em.
Tam j¹ zostawcie samotn¹, by zmar³a
Albo te¿¿ywa pêdzi³a dni marne;
Tak wobec dziewki zostaniemy bez winy,
A nie cierpimy, aby wœród nas ¿y³a.


30



Antygona

Grobie, ty mojej ³o¿nico mi³oœci,
Mieszkanie wieczne, ciemnico sklepiona!
Idê do moich, których tylu goœci
W pozgonnych domach boska Persefona.
Za wami idê ja, co w ¿ycia wioœnie
Zginê³am, prawie nie zaznawszy œwiata.
A tuszê, ¿e mnie tam przyjm¹ radoœnie,
Ty, ojcze, matko, i mi³a d³oñ brata:
Bom tu z mi³osn¹ s³u¿b¹ wasze cia³a
W³asn¹ obmy³a, namaœci³a rêk¹;
¯em bratnie zw³oki uczciwie grzeba³a,


Tak¹ mnie darz¹ podziêk¹!
Mam u szlachetnych ludzi czeœæ i chwa³ê,
Lecz potêpienie ze strony Kreona,
Bo on me czyny uzna³ za zuchwa³e.
Rêk¹ wiêc jego teraz uwiêziona,
Ani zaznawszy s³odyczy wesela,
Ni uczuæ matki, ni dziatek pieszczoty,
Schodzê tak sama i bez przyjaciela,
Nieszczêsna, ¿ywa do grobowej groty.
Jakie¿ to bogów z³ama³am ustawy?
Jak¿e do bogów podnosiæ mam mod³y,
Wo³aæ o pomoc, je¿eli czyn prawy,
Który spe³ni³am, uznano za pod³y?
Lecz jeœli z bogów to zrz¹dzenia p³ynie,
Trzeba mi winnej znieœæ w ciszy cierpienia.
Jeœli ci b³¹dz¹, niech siêgnie ich w winie

KaŸñ równa z bogów ramienia!

Przodownik Chóru

Te same burze i te same jeszcze
Dusz¹ tej dziewki wci¹¿ miotaj¹ dreszcze.

Kreon

Pacho³ki, którym wieœæ j¹ nakaza³em,
Swoj¹ powolnoœæ ciê¿ko mi... odp³acz¹.

Antygona

Biada! Ta mowa gro¿¹ca
Bliskiego wró¿b¹ mi koñca.

Przodownik Chóru

A ja odwagi nie œmia³bym dodawaæ,
¯e siê te srogie ukazy odwlok¹.

Antygona

Ziemi tebiañskiej ojczysty ty grodzie
I wy, bogowie rodowi!


Oto mnie wiod¹ w bezzw³ocznym pochodzie
Ku samotnemu grobowi.
Patrzcie na ksiê¿nê ostatni¹ z Teb królów,
W rêce siepaczy ujêta,
Ile m¹k ona, ile znios³a bólów
Za wiern¹ s³u¿bê i œwiêt¹.

Wyprowadzaj¹ A n t y g o n ê .

[Stasimon IV]

Chór

Tak i Danae jasnego dna zorze
Zmieniæ musia³a na loch w miedŸ obity,

W grobowej skryta komorze.
A przecie¿ ród jej zapewnia³ zaszczyty
I Zeus deszcz z³oty na ³ono jej roni.

Straszne przeznaczeñ obierze!
Pieni¹dz ni si³a, ni warowne wie¿e,
Ni morski ¿agiel przed nimi nie chroni.

Edonów króla Likurga te¿ bucie,
¯e hardym s³owem na boga siê miota,
Bakchos kamienne zgotowa³ okucie,
Gdzie z³a wykipi ochota.
Rozpozna³ on tam za póŸno swe zbrodnie
I po¿a³owa³ s³ów gniewu,
Chcia³ bo sza³ boski t³umiæ i pochodnie,
Ur¹ga³ Muzom wœród œpiewu.

Gdzie z mórz strzelaj¹ kyanejskie progi,
Kraj Salmidesu, dla przybyszów wrogi,
Gdzie brzeg Bosforu ba³wany roztr¹ca,
Tam widzia³ Ares, jak dzikoœci¹ wraca
¯ona Fineusa pasierby swe nêka.
Nie mieczem srogim wymierza im ciêgi,
Lecz krwaw¹ rêkê zatapia w ócz krêgi,
Ostrzem je ³upi czó³enka.

Ujêci oni kamienn¹ niewol¹,
P³acz¹ nad matki i swoj¹ niedol¹.
Przecie¿ jej przodki z Erechtydów rodu,
Ojcem Boreasz; poœród ska³ i g³ogów,


I burz pêdzi³a dni swoje od m³odu,

Na chy¿ych koniach – prawe dzieciê bogów.
Jednak choæ w dali, i tu jej dosiêga

Odwiecznej Moiry potêga.

Wchodzi T y r e z j a s z .

[Epeisodion V]

Tyrezjasz

Œlepy wiedziony przez ch³opca

O Teb starszyzno, wspólnym my tu krokiem
I wspólnym wzrokiem zd¹¿amy, bo ciemnym
Za oko staje przewodnika rêka.

Kreon

Có¿ tam nowego, Tyrezjaszu stary?

Tyrezjasz

Ja rzeknê, ty zaœ pos³uchaj wró¿biarza.

Kreon

Nigdy twoimi nie wzgardzi³em s³owy.

Tyrezjasz

Przeto szczêœliwie sterujesz t¹ naw¹.

Kreon

Przeœwiadczyæ mogê, doznawszy korzyœci.

Tyrezjasz

Zwa¿ teraz, znowu stoisz na prze³omie.

Kreon

Co mówisz? Trwog¹ przejmuj¹ twe s³owa.

Tyrezjasz

Poznasz tê prawdê ze znaków mej sztuki.
Siad³em na starej wró¿bity siedzibie,
Gdzie wszelkie ptactwo kieruje swe loty.
A¿ naraz s³yszê, jak niezwyk³e g³osy
Wydaj¹ ptaki, szalone i dzikie;
I wnet pozna³em, ¿e szarpi¹ siê szpony,


33



Bo ³opot skrzyde³ to stwierdza³ dobitnie.
Przejêty trwog¹, próbujê ofiary
Na p³omienistym o³tarzu, lecz ogieñ
Nie chce wystrzeliæ ku górze, a s¹czy
Ciecz z miês ofiarnych, wsi¹kaj¹c w popio³y,
Kipi i syczy, ¿ó³æ bryzga w powietrze
I spoza t³uszczu, co sp³yn¹³ stopiony,
Uda wyjrza³y na o³tarzu nagie.
Od tego ch³opca wnet siê dowiedzia³em,
¯e takie marne sz³y z ofiary znaki,
Bo on przewodzi mnie, a ja znów innym.
Tak wiêc chorzeje miasto z twojej winy.
Bo wsze o³tarze i ofiarne sto³y
Psy pokala³y i ptactwo, co cia³em
Edypowego siê¿ywi³o syna.
Wiêc nie przyjmuj¹ ju¿ ofiarnych mod³ów
Bogowie od nas ni ofiarnych dymów.
A ptak, co ¿³opa³ krew trupa zastyg³¹,
Ju¿ nie wydaje g³osów dobrej wró¿by.
Rozwa¿ to, synu; bo wszystkich jest ludzi
B³¹dziæ udzia³em i z prostej zejœæ drogi;
Lecz m¹¿, co zb³¹dzi³, nie jest pozbawiony
Czci i rozwagi, je¿eli wœród nieszczêœæ
Szuka lekarstwa i nie trwa w uporze.
Upór jest zawsze nierozumu znakiem;
Ust¹p ty œmierci i nie dra¿ñ zmar³ego:
Có¿ bo za chwa³a nad trupem siê znêcaæ?
¯yczliwoœæ moja t¹ rad¹ ci s³u¿y;
Dobrze jej s³uchaæ, gdy korzyœci wró¿y.


Kreon

Starcze, wy wszyscy jak ³ucznik do celu
Mierzycie we mnie; teraz i wró¿biarstwo
Sid³a zastawia, a krewni m¹ myœl¹
Kupcz¹, frymarcz¹ z dawna jak towarem.
Nu¿e, gromadŸcie wy sardyjskie skarby,
Wska¿cie mi górê indyjskiego z³ota,
Na pogrzeb tego jednak nie zezwolê.
I choæby or³y Zeusowe porwa³y
Trupa i przed tron Zeusowi zanios³y,
Ja siê takiego nie ulêknê sromu,
Grzeœæ nie pozwolê; wiem bo ja zbyt dobrze:
Bogów zbezczeœciæ nie zdo³a œmiertelny,
Potkn¹æ siê mog¹ i ludzie przem¹drzy,
Starcze, haniebne, kiedy szpetne myœli
Ubior¹ w s³owa barwiste... dla zysku.



Tyrezjasz

Biada!
Czy¿ wie cz³owiek, czy rozwa¿a sobie...

Kreon

Có¿, z jakim znowu na plac ogólnikiem?

Tyrezjasz

Ile rozs¹dek góruje nad skarby?

Kreon

O ile klêsk¹ najwiêksz¹ nierozum.

Tyrezjasz

Ciê¿ko ty na tê zapad³eœ chorob¹.

Kreon

Nie chcia³bym ciê¿kim obraziæ ciê s³owem.

Tyrezjasz

Czynisz to, kiedy mi k³amstwo zarzucasz.

Kreon

Bo cech wasz ca³y ³apczywy na zyski.

Tyrezjasz

A ród tyranów w mêtach chciwie ³owi.

Kreon

Wiesz, ¿e ty pana twojego obra¿asz?

Tyrezjasz

Wiem, bo ja tobie gród ten zachowa³em.

Kreon

M¹dry ty wró¿biarz, lecz oddany z³emu.

Tyrezjasz

Tyœ gotów wydrzeæ mi z wnêtrza tajniki.

Kreon

Wyrusz ty z nimi, byle nie dla zysku.

Tyrezjasz

¯e ty st¹d zysku nie uszczkniesz, to myœlê.

Kreon

Bacz, ¿e zamys³ów moich nie stargujesz.


Tyrezjasz

Wiedz wiêc stanowczo, ¿e nim s³oñce tobie
Wielu dokona ko³owych obrotów,
P³ód z twoich w³asnych poczêty wnêtrznoœci
Jak trupa oddasz w zamianê za trupy;
Za to, ¿e z œwiat³a str¹ci³eœ do nocy,
Zamkn¹³eœ¿ycie haniebnie w grobowcu,
A tu na ziemi zmar³e trzymasz cia³o,
Które siê bóstwom nale¿y podziemnym.
Nie masz ¿adnego ty nad zmar³ym prawa
Ni œwiat³a bogi, którym gwa³t zadajesz.
Za to czyhaj¹ Hadesa i bogów
Mœciwe i zgub¹ gro¿¹ce Erynie,
By ciê w podobnym pogr¹¿yæ nieszczêœciu.
Poznasz ty wkrótce, czy ja przekupiony
Tak mówiê, w krótkim poka¿¹ to czasie
Mê¿czyzn i niewiast w twoim domu jêki.
A wszelkie miasto przeciw tobie stanie,
W którym psy strzêpy zbezczeœci³y trupów,
Zwierzêta dzikie i ptactwo, roznosz¹c
Wstrêtne po œwiêtych zaduchy ogniskach.
Takimi strza³y ja, ciê¿ko zel¿ony,
Godzê jak ³ucznik z gniewem w twoje serce
I jak celujê, ¿e ostrze poczujesz.
O ch³opcze, wiedŸ¿e mnie teraz do domu,
Bo on na m³odszych swe gniewy upuœci³,
A lepiej odt¹d miarkowa³ siê w s³owie
I myœl mu lepsza zajaœnia³a w g³owie.


T y r e z j a s z odchodzi.

Przodownik Chóru

O w³adco, poszed³ on po wró¿bie strasznej.
A wiem to, odk¹d mi czarne siwizn¹
Staroœæ na g³owie posrebrzy³a w³osy:
Fa³szu on nigdy nie zwiastowa³ miastu.

Kreon

Ja te¿ wiem o tym i trwoga mn¹ miota.
Ust¹piæ ciê¿ko, a jeœli siê oprê,
To ³atwo klêska roztr¹ci m¹ czelnoœæ.


Przodownik Chóru

Synu Menoika, rozwagi ci trzeba.

Kreon

Có¿ tedy czyniæ? Mów pójdê za rad¹.


Przodownik Chóru

IdŸ i wyprowadŸ dziewkê z ciemnej groty,
A grób przygotuj dla cia³a co le¿y.

Kreon

Radzisz i mniemasz, ¿e ja mam ust¹piæ?

Przodownik Chóru

O, jak najprêdzej, mój ksi¹¿ê, bo chy¿o
KaŸñ bogów ludzkich pochwyci nierozum.

Kreon

Ciê¿kie to, ale ka¿ê milczeæ sercu;
Cofnê siê, trudno z koniecznoœci¹ walczyæ.

Przodownik Chóru

IdŸ, sam to uczyñ, nie zwalaj na innych.

Kreon

Idê sam, zaraz; a wy, moi s³udzy,
Wzi¹wszy topory poœpieszcie pospo³em
Na miejsce widne, gdzie nagi trup le¿y.
Ja, ¿e zmieni³em me dawne zamys³y,
Com sam namota³, sam teraz rozwi¹¿ê.
Najlepiej mo¿e dzia³a, to do zgonu
Praw istniej¹cych przestrzegaj¹ zakonu.

Wychodzi w towarzystwie s³u¿by.

[Stasimon V]

Chór

Wieloimienny, coœ z Kadmosa domu
Przysporzy³ chwa³y dziewczynie,
Synu ty Zeusa, pana burz i gromu!
W italskiej ziemi twoje imiê s³ynie,

A i w Eleuzis, o synu Semeli,

Roje ciê s³awi¹ czcicieli.

Bakchosie, w Tebach ty dzier¿ysz stolicê,
Kêdy Ismenos ciche wody toczy;
Sza³em twym tchn¹ce pl¹saj¹ dziewice,


Pieniem rozbrzmiewa gród smoczy.


Widnyœ ty w ³unie jarz¹cych kagañców,
Gdzie Parnas szczytem dwug³owym wystrzela,
Gdzie zdrój Kastalii i swawolnych tañców
Koryku nimfy zawodz¹ wesela.


W górach nysejskiej Eubei
W spowitej bluszczem mkniesz kniei,


Potem z tych brzegów, gdzie bujne winnice,
Zwrócisz swe kroki ku Tebom;
Pieœni ciê chwa³y wiod¹ przez ulice


I brzmi¹ radoœnie ku niebom.
Gród ten nad wszystkie czcisz grody na œwiecie
Wraz z matk¹ twoj¹ ciê¿arn¹ od gromu;
Kiedy wiêc brzemiê nieszczêœcia nas gniecie
Pe³nego cierpieñ i sromu,
Przyb¹dŸ z Parnasu ku naszej obronie
Lub przez wyj¹ce mórz tonie.

Ty, co przodujesz wœród gwiazd korowodu,
Pieœniom przewodzisz wœród mroczy,
Zawitaj, synu Zeusowego rodu!
Niechaj ciê zastêp naksyjskich otoczy
Tyjad, co w szale od zmierzchu do rana
Tañcz¹ i w tobie czcz¹ pana.

Wchodzi P o s ³ a n i e c .

[Exodos]

Pos³aniec

O kadma grodu, domu Amfiona
Mieszkañcy! ¯ycia cz³owieka nie œmia³bym
Ani wys³awiaæ, ni ganiæ przenigdy:
Bo los podnosi i los znów pogr¹¿a
Bez przerwy w szczêœcie ludzi i w nieszczêœcia,
A nikt przysz³oœci wywró¿yæ niezdolny.
Tak Kreon zdawa³ siê godnym podziwu,
On, co wyzwoli³ tê ziemiê od wrogów
I jako w³adca jedyny nad krajem
Rz¹dzi³, potomstwem ciesz¹c siê kwitn¹cym.
A dziœ to wszystko – stracone. Bo radoœæ
Jeœli w cz³owieku przygaœnie, to trzymam,
¯e on nie ¿yje, lecz ¿ywym jest trupem.



GromadŸ bogactwa do woli w twym domu,
Œwieæ jako w³adca na zewn¹trz: gdy cieszyæ
Tym siê nie mo¿na, to reszty tych skarbów
Ja bym nie naby³ za dymu cieñ marny.

Przodownik Chóru

Jak¹¿ ty znowu wieœæ niesiesz z³¹ ksiêciu?

Pos³aniec

Skoñczyli... Œmierci ich winni, co ¿yj¹.

Przodownik Chóru

Któ¿ to morderc¹, któ¿ poleg³? O, rzeknij!

Pos³aniec

Haimon nie ¿yje, we w³asnej krwi broczy.

Przodownik Chóru

Z ojca czy z w³asnej zgin¹³¿e on rêki?

Pos³aniec

W gniewie na ojca mordy sam siê zabi³.

Przodownik Chóru

Wró¿bito, jak¿eœ czyn trafnie okreœli³!

Pos³aniec

W tym rzeczy stanie dalszej trza narady.

Przodownik Chóru

Lecz oto widzê biedn¹ Eurydykê,
¯onê Kreona; albo siê przypadkiem
Pojawia, albo s³ysza³a o synu.

Z pa³acu wychodzi E u r y d y k a .

Eurydyka

 Starcy, rozmowy waszej pos³ysza³am
W³aœnie, gdym z domu wybiec zamierza³a,
By do Pallady z mod³ami siê zwróciæ.
I w³aœnie odrzwi odmykam zasuwki,
By je roztworzyæ, gdy nagle nieszczêsna
Wieœæ uszy rani; wiêc pad³am, zemdlona
Z trwogi, w objêcia mych wiernych s³u¿ebnic.
Powtórzcie tedy, co ta wieœæ przynosi;
W z³ym doœwiadczona, wys³ucham s³ów waszych.

Pos³aniec

Ja, mi³oœciwa pani, by³em przy tym,
Powiem wiêc wszystko, jak siê wydarzy³o;

39



Có¿ bo ukrywaæ, by potem na k³amcê
Wyjœæ? Przecie prawda zawsze fa³sz przemo¿e.
Ja tedy wiod³em twojego ma³¿onka
Na ten pagórek, gdzie biedne le¿a³o,
Przez psy podarte, cia³o Polinika.
Wnet do Hekaty zanieœliœmy mod³y
I do Plutona, by gniew ich z³agodziæ;
Obmywszy potem cia³o w œwiêtej wodzie,
Palimy szcz¹tki na stosie z ga³êzi
I grób z ojczystej sypiemy im ziemi.
To uczyniwszy, zaraz do kamiennej
Œlubno-grobowej ³o¿nicy dziewczyny
Œpieszymy. Z dala ktoœ jêki us³ysza³
Od strony lochu, co za grób mia³ s³u¿yæ,
Choæ nie œwiêci³y go ¿adne obrzêdy.
Wraz wiêc donosi panu, co zas³ysza³.
Tego dochodz¹ zaœ, kiedy siê zbli¿y³,
£kania ¿a³osne, a pierœ mu wybucha
G³osem rozpaczy: „O, ja nieszczêœliwy!
Czym odgad³ prawdê? Czy¿ nie kroczê teraz
Drog¹ najwiêkszej w ¿ywocie mym klêski?
Syna wo³anie mnie mrozi. O s³udzy,
Œpieszcie wy naprzód, zbli¿cie siê do grobu
I przez szczelinê g³azem zawalon¹
Wszed³szy do wnêtrza, baczcie, czy Haimona
G³osy ja s³yszê, czy bogi mnie durz¹”.
Pos³uszni woli zw¹tpia³ego pana,
Idziem na zwiad, a w grobowca g³êbi
Dojrzym wnet dziewkê, wisz¹c¹ za gard³o,
Œciœniête wêz³em muœlinowej chusty,
Podczas gdy m³odzian uchwyci³ j¹ wpo³y,
Boleœnie jêcz¹c nad szczêœcia utrat¹,
Nad czynem ojca, nieszczêsnymi œluby.
Kreon, zoczywszy to, ciê¿ko zajêkn¹³,
Rzuca siê naprzód i wœród ³kania wo³a:
„O ty nieszczêsny! Có¿eœ ty uczyni³!
Czy sza³ ciê jaki opêta³ z³owrogi?
WychodŸ, o synu, b³agalnie ciê proszê!”
Lecz syn na niego dzikim ³ysn¹³ wzrokiem
I twarz przekrzywi³, a s³owa nie rzek³szy
Ima siê miecza: wraz ojciec ucieczk¹
Uszed³ zamachu; natenczas nieszczêsny
W gniewie na siebie nad ostrzem siê schyla
I miecz w bok wra¿a; lecz jeszcze w konaniu
Drêtwym ramieniem do zmar³ej siê tuli,
A z ust dysz¹cych wytryska mu struga
Krwawa na blade kochanki policzki.


E u r y d y k a wybiega do pa³acu.

Trup dziœ przy trupie, osi¹gn¹³ on œluby,


W domu Hadesa z³o¿ony przy lubej.
Nieszczêœciem dowiód³, ¿e wœród ludzi t³umu
Najwiêksze klêski p³yn¹ z nierozumu.


Przodownik Chóru

A có¿ st¹d wró¿ysz, ¿e znika niewiasta,
Nie rzek³szy z³ego lub dobrego s³owa?

Pos³aniec

I ja siê dziwiê, lecz ¿ywiê nadziejê,
¯e pos³yszawszy o ciosie, nie chcia³a
¯a³oœci swojej pospólstwu okazaæ,
Lecz siê cofnê³a do wnêtrza domostwa,
By wœród s³ug wiernych wylewaæ³zy gorzkie.
Toæ jej rozwaga nie dopuœci b³êdu.


Przodownik Chóru

Nic nie wiem, ale milczenie uporne,
Jak i zbyt g³oœne jêki, z³o mi wró¿¹.

Pos³aniec

Wnet siê dowiemy, czy w g³êbiach rozpaczy
Nie kryje ona tajnego zamys³u.
IdŸmy do domu, bo dobrze ty mówisz:
Nadmierna cisza, jest g³osem z³owrogim.


Odchodzi do pa³acu. Wchodzi K r e o n , dŸwigaj¹c cia³o syna, za nim s³udzy.

Przodownik Chóru

Lecz otó¿ ksi¹¿ê tu w³aœnie nadchodzi;

O! Znak wymowny uj¹³ on ramiony,
Nie cudzej zbrodni, jeœli rzec siê godzi,
Lecz w³asnej winy szalonej.

Kreon

Klnê moich myœli œmierciodajne winy,
Co zatwardzi³y mi serce!
Widzicie teraz wœród jasnej rodziny

Ofiary, ofiar mordercê.
S³owo dziœ moje me czyny przeklina:
W samym, o! ¿ycia rozkwicie
Przedwczesne losy porwa³y mi syna,

Mój ob³êd zmia¿d¿y³ to ¿ycie.

Przodownik Chóru

PóŸno siê zdajesz poznawaæ, co s³uszne.

Kreon

Biada mi!

41



Przejrza³em biedny: jaki¿ bóg z³owrogi
Zwali³ na g³owê m¹ brzemiê,
Na sza³u popchn¹³ mnie drogi,
Szczêœcie mi zdepta³, wbi³ w ziemiê.
O biada! Do zguby
Wiod¹œmiertelnych rachuby.


Z pa³acu wychodzi P o s ³ a n i e c .

Pos³aniec

Panie! Ty nieszczêœæ masz wielkie zasoby,
Bo jedyne dŸwigasz w twych rêkach nieszczêsnych,
A drugie ujrzysz niebawem w twym domu.


Kreon

Czy¿ ja nie na dnie ju¿ nieszczêœcia g³êbi?

Pos³aniec

Nie masz ju¿¿ony; syna twego matka
W³aœnie na swoje targnê³a siê¿ycie.

Kreon

Nieub³agana przystani, Hadesie,
Gdzie¿ koniec moich boleœci?
O! Znowu nowe mi ten niesie
Godz¹ce w serce mi wieœci.
W mê¿a, co leg³ ju¿, wtórnym godzisz ciosem,
Z³owrogim s³owem i g³osem.
Biada! Nieszczêœcie z nieszczêœcia siê s¹czy,
Z synem œmieræ¿onê ³¹czy.


Przodownik Chóru

Widzieæ to mo¿esz, dom stoi otworem.

Kreon

Z³e siê jak burza nade mn¹ zerwa³o,
Nie widzê koñca mej mêce:
Syna zmar³ego dŸwiga³em ja rêce,
A teraz ¿ony martwe widzê cia³o.
O biada! Matczyna
Rozpacz dogna³a ju¿ syna.


Pos³aniec

Zranionej ciê¿ko noc¹ zasz³y oczy,
U stóp o³tarza zajêk³a nad zgonem
Niegdyœ chwalebnym syna Megareusa
I nad Haimonem, a wreszcie przekleñstwa
Tobie rzuci³a ciê¿kie, dzieciobójcy.

42



Kreon

Groza mn¹ trzêsie. Przecz mieczem nikt w ³ono
Ciosu mi œmierci nie zada?
O, ja nieszczêsny! O biada mi, biada!
W toñ nieszczêœæ sunê spienion¹.

Pos³aniec

W konaniu jeszcze za te wszystkie zgony
Na twoj¹ g³owê miota³a przekleñstwa.

Kreon

Jakim¿e ona skoñczy³a sposobem?

Pos³aniec

¯elazo w w³asnej utopi³a piersi,
S³ysz¹c o syna op³akanym koñcu.

Kreon

O biada! Win mi nie ujmie nikt inny,
Nie ujmie mêki ni kaŸni!
Ja bo nieszczêsny, ja twej œmierci winny,
Nu¿e, o s³udzy, wiedŸcie mnie co raŸniej,
UwodŸcie mnie st¹d; niech moim obliczem
Nie mier¿ê, ja, co mniej jestem jak niczym!

Przodownik Chóru

Zysku ty szukasz, jeœli zysk w nieszczêœciu,
Bo l¿ejsza klêska, co nie gnêbi d³ugo.

Kreon

B³ogos³awion dzieñ ów, który nêdzy
Kres ju¿ ostatni po³o¿y.
Przyb¹dŸ, o przyb¹dŸ co prêdzej,
Niechbym nie ujrza³ jutrzejszej ju¿ zorzy!


Przodownik Chóru

To rzecz przysz³oœci, dla obecnej chwili
Trza dzia³aæ; tamto obmyœliæ – rzecz bogów.

Kreon

Wszystkie pragnienia w tym jednym zawar³em.

Przodownik Chóru

O nic nie b³agaj, bo pró¿ne marzenia,
By cz³owiek uszed³ swego przeznaczenia.


Kreon

WiedŸcie mnie, s³ugi, uchodŸcie st¹d ze mn¹,
Mnie, który syna zabi³em wbrew woli


I tamt¹. Biada! A¿ w oczach mi ciemno.
Dok¹d siê zwróciæ, gdzie spojrzeæ w niedoli?
Wszystko mi ³amie siê w rêku,
Los nie powali³, pe³en burz i lêku.


Chór

Nad szczêœcia b³ysk, co z³ud¹ mar, najwy¿szy skarb – rozumu dar.
A wyzwie ten niechybny s¹d,
Kto bogów l¿y i wali rz¹d.
I zeœl¹ oni sw¹ zemstê i kary
Na pychê s³owa w cz³owieku,
I w klêsk odmêcie – rozumu i miary
W póŸnym naucz¹ go wieku.


44


"""
antygona = antygona.encode('utf-8')
def xor(a, b):
    return bytes([a ^ b for a, b in zip(a, b)])


def check_pcap(file_name):
    try:
        scapy_cap = rdpcap(file_name)
    except (Scapy_Exception, FileNotFoundError):
        print("Niepoprawny plik!", file=sys.stderr)
        sys.exit(1)

    pkts = [scapy_cap[i:i+2] for i in range(0, len(scapy_cap), 2)]
    correct = []
    for pkt_pair in pkts:
        p1 = pkt_pair[0]
        p2 = pkt_pair[1]

        new_xored_data = b''
        for i in range(MSG_SIZE):
            new_xored_data += p2[UDP].load[i*2].to_bytes(1, 'big')
        xor_pattern = bytes.fromhex((MSG_SIZE // 2) * hex(p1[UDP].chksum)[2:].zfill(4))
        data = xor(new_xored_data, xor_pattern)
        if b'....' in data:
            data = data[:64].split(b'....')[0]
        correct.append(bool(data in antygona))


    return all(correct)

if __name__ == '__main__':
    if len(sys.argv) < 2 or str(sys.argv[1]) in ('h', 'help', 'pomoc'):
        print("Uzycie: pcap_checker.exe <nazwa_pliku_pcap>")
        print("Sprawdza czy kazdy pakiet w pliku zawiera dane stenograficzne Antygony")
        sys.exit(0)
    else:
        print(
            "Antygona w pakietach" if check_pcap(str(sys.argv[1])) else "Brak Antygony w pakietach"
        )
# for i in range(1, 15):
#     print(f"{i} ", end='')
#     print(
#         check_pcap(f"pcap/p{i}.pcap")
#     )



