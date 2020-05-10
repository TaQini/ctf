#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

//gcc -O0 -Wl,-z,relro,-z,now -fno-stack-protector-all -o ../ressources/kikoo_4_ever kikoo_4_ever.c

#define REGLE_BUF_SIZE_512 512
#define LIEUX_BUF_SIZE_48 48
#define ARRAY_SIZE_100 100
#define TINY_ARRAY_SIZE_5 5

typedef struct regle{
  char regle[REGLE_BUF_SIZE_512];
  int locked;
}Regle;

typedef struct lieux{
  char nom[LIEUX_BUF_SIZE_48];
  int visite;
  char initiale;
}Lieux;

typedef struct kikoos_observe{
  char pseudos[10][32];
  char observations[10][128];
  int n_observation;
}Kikoos_observe;

Regle *les_regles_du_kikoo[ARRAY_SIZE_100];
Lieux les_lieux_du_kikoo[TINY_ARRAY_SIZE_5];
Kikoos_observe kikoos_observe;

int read_user_int(){
	char buf[9];
	int i;

	fgets(buf, 8, stdin);
	i = atoi(buf);

	return i;
}

void read_user_str(char* s, int size){
	char *ptr = NULL;
	read(0, s, size);
	ptr = strchr(s, '\n');
	if(ptr != NULL)
		*ptr = 0;
  //Si il y a pas de \n c'est qu'il a rempli le buffer au max du max, enfin j'crois
  else
    s[size] = 0;
}


int get_free_index(void **tab){
  for(int i = 0 ; i < ARRAY_SIZE_100 ; i++){
    if(tab[i] == NULL)
      return i;
  }
  return -1;
}

void ajouter_observation(char *pseudo, char *observation){
  strncpy(kikoos_observe.pseudos[kikoos_observe.n_observation], pseudo, 32);
  strncpy(kikoos_observe.observations[kikoos_observe.n_observation], observation, 128);
  kikoos_observe.n_observation++;
}

void lire_observations(){
  if(kikoos_observe.n_observation <= 0){
    puts("No interesting observations at this time.");
    return;
  }

  for(int i = 0 ; i < kikoos_observe.n_observation ; i++){
    printf("Observation n°%d:\n\tNickname: %s\n\tNote: %s\n", (i+1), kikoos_observe.pseudos[i], kikoos_observe.observations[i]);
  }
}

void creer_lieux(int i, char *nom, int visite, char initiale){
  Lieux *lieux;

  lieux = &les_lieux_du_kikoo[i];

  memcpy(lieux->nom, nom, LIEUX_BUF_SIZE_48);
  lieux->visite = visite;
  lieux->initiale = initiale;
}

Regle* creer_regle(char *str_regle, int locked){
  Regle *regle = NULL;
  int i = -1;

  i = get_free_index((void**)les_regles_du_kikoo);
  if(i == -1){
    puts("The list of rules is full.");
    return NULL;
  }

  regle = malloc(sizeof(Regle));
  if(regle == NULL){
    return NULL;
  }

  memcpy(regle->regle, str_regle, REGLE_BUF_SIZE_512);
  regle->locked = locked;

  les_regles_du_kikoo[i] = regle;
  return regle;
}

void ecrire_regle(){              // write rules
  char buf[REGLE_BUF_SIZE_512];
  int i;
  char go_on[8] = "n";
  Regle *regle = NULL;

  if(kikoos_observe.n_observation == 0){
    puts("What are you going to write? We haven't found anything interesting yet.");
    puts("Let's go find some kikoo.");
    return;
  }

  i = get_free_index((void**)les_regles_du_kikoo);
  if(i == -1){
    puts("The list of rules is full.");
    return;
  }

  puts("\nMake me dream, what's that rule?");
  do{
    printf("Rule n°%d: ", (i+1));
    read_user_str(buf, REGLE_BUF_SIZE_512+0x10);
    printf("Read back what you just wrote:\n%s\n", buf);
    printf("Is it ok? Shall we move on? (y/n)");
    read_user_str(go_on, 4);
  }while(go_on[0] != 'y');

  regle = creer_regle(buf, 1);    // buf 512 strcpy to regle
  les_regles_du_kikoo[i] = regle; 
}

void init_buffering(){
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
}

void scenario_j(){
  ajouter_observation("jer75emy", "Mature Kikoo");
  ajouter_observation("Kankan776", "High level Kikoo, owner of a minecraft pvp faction server.");
}

void scenario_y(){
  // nop
}

void scenario_t(){
  // nop
  ajouter_observation("Kankan776", "This kikoo seems to me to respect several rules of the notebook, to be analyzed in depth.");
  ajouter_observation("zguegenbronze", "High quality Kikoo, not to be approached, very high risk of contamination.");
  ajouter_observation("Palagrosdindon", "Excellent Kikoo troller, beware.");
}

Lieux* get_lieux(char initiale){
  for(int i = 0 ; i < TINY_ARRAY_SIZE_5 ; i++){
    if(les_lieux_du_kikoo[i].initiale == initiale)
      return &les_lieux_du_kikoo[i];
  }
  return NULL;
}

void lister_les_lieux(){
  for(int i = 0 ; i < TINY_ARRAY_SIZE_5 ; i++){
    if(les_lieux_du_kikoo[i].visite == 1)
      printf("\t#%c : %s\n", les_lieux_du_kikoo[i].initiale, les_lieux_du_kikoo[i].nom);
  }
}

void choisir_lieux(){

  int go_on = 1;
  char choix[8];
  Lieux *lieux = NULL;

  puts("");
  lister_les_lieux();
  puts("Type Q to exit.");
  do{
    printf("> ");
    read_user_str(choix, 4);

    lieux = get_lieux(choix[0]);

    if(choix[0] == 'J' && lieux != NULL && lieux->visite == 1){
      go_on = 0;
      scenario_j();
      lieux->visite = 2;
    }
    else if(choix[0] == 'Y' && lieux != NULL && lieux->visite == 1){
      go_on = 0;
      scenario_y();
      lieux->visite = 2;
    }
    else if(choix[0] == 'T' && lieux != NULL && lieux->visite == 1){
      go_on = 0;
      scenario_t();
      lieux->visite = 2;
    }
    else if(choix[0] == 'Q'){
      go_on = 0;
    }
    else{
      puts("Choice not available.");
    }

  }while(go_on);
}

void lire_les_regles(){

  puts("\nThe Rules of the Holy Kikoo:");
  for(int i = 0 ; i < ARRAY_SIZE_100 && les_regles_du_kikoo[i] != NULL ; i++){
    printf("Rule n°%d: %s\n", (i+1), les_regles_du_kikoo[i]->regle);
  }
}

void introduction(){

  lire_les_regles();

}

void initialisation(){
  init_buffering();
  creer_regle("A kikoo who has never played Minecraft in his life is not a kikoo.", 1);
  creer_regle("A kikoo has necessarily maintained at least one discussion on the forum jeuxvideo.com.", 1);
  creer_regle("Every self-respecting kikoo has already been banned from an online video game for the reason: Cheat.", 1);
  creer_regle("A kikoo could find his login credentials in database leaks.", 1);
  creer_regle("A kikoo enjoys the annoyance of his friends.", 1);
  creer_lieux(0, "Long-standing topics on jeuxvideo.com.", 1, 'J');
  creer_lieux(1, "Stupid YouTube channels.", 1, 'Y');
  creer_lieux(2, "Minecraft streams on Twitch.", 1, 'T');
  kikoos_observe.n_observation = 0;
}

void choix(){
  printf("\n==What do we do?==\n" \
				 " 1 -> Rereading the rules\n" \
				 " 2 -> Write a rule\n" \
				 " 3 -> We're going hunting\n" \
         " 4 -> View comments\n" \
				 " 9 -> I'm out of here.\n" \
				 "==================\n\n"
	);
}

int main(void){

  char tmp[64];
  int choice;
  int go_on = 1;

  initialisation(); // create rules & create lieux
  introduction();   // show rules
  choisir_lieux();  // choose lieux(place?)

	while(go_on){
    choix();        // menu
		printf("> ");
		choice = read_user_int(); 

		switch (choice) {
			case 1:
        lire_les_regles();  // show rules
				break;
			case 2:
        ecrire_regle();     // add rule
				break;
			case 3:
        choisir_lieux();    // choose lieux
				break;
      case 4:
        lire_observations();// show obs
  			break;
			case 9:
        go_on = 0;
				break;
			default:
				printf("\nDon't get what you're trying to do, buddy.\n\n");
				break;
		}
	}
  return 0;
}
