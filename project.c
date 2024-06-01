#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/evperr.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
char* sha256file(char* file) {
	// Créer un nom de fichier temporaire
	char tempFileName[] = "/tmp/temp_fileXXXXXX";
	int tempFile = mkstemp(tempFileName);
	if (tempFile == -1) {
		perror("Erreur lors de la création du fichier temporaire");
		exit(EXIT_FAILURE);
	}
	
	// Copier le contenu du fichier spécifié vers le fichier temporaire
	FILE* inputFile = fopen(file, "r");
	FILE* tempFilePtr = fdopen(tempFile, "w");
	if (!inputFile || !tempFilePtr) {
		perror("Erreur lors de l'ouverture des fichiers");
		exit(EXIT_FAILURE);
	}
	#define BUFFER_SIZE 4096
	
	char* calculateFileHash(const char* file_path) {
		FILE* file = fopen(file_path, "rb");
		if (file == NULL) {
			perror("Error opening file");
			return NULL;
		}
		
		// Initialize SHA-256 context
		SHA256_CTX sha256_ctx;
		if (!SHA256_Init(&sha256_ctx)) {
			fclose(file);
			fprintf(stderr, "Error initializing SHA-256 context\n");
			return NULL;
		}
		
		// Buffer for reading file data
		unsigned char buffer[BUFFER_SIZE];
		size_t bytes_read;
		
		// Read file in chunks and update hash
		while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, file)) > 0) {
			if (!SHA256_Update(&sha256_ctx, buffer, bytes_read)) {
				fclose(file);
				fprintf(stderr, "Error updating SHA-256 context\n");
				return NULL;
			}
		}
		
		// Finalize hash
		unsigned char hash[SHA256_DIGEST_LENGTH];
		if (!SHA256_Final(hash, &sha256_ctx)) {
			fclose(file);
			fprintf(stderr, "Error finalizing SHA-256 context\n");
			return NULL;
		}
		
		// Convert hash bytes to hexadecimal string
		char* hash_string = (char*)malloc((SHA256_DIGEST_LENGTH * 2 + 1) * sizeof(char));
		if (hash_string == NULL) {
			fclose(file);
			perror("Memory allocation error");
			return NULL;
		}
		
		for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
			sprintf(&hash_string[i * 2], "%02x", hash[i]);
		}
		hash_string[SHA256_DIGEST_LENGTH * 2] = '\0'; // Null-terminate string
		
		fclose(file);
		return hash_string;
	}

	
	char buffer[1024];
	size_t bytesRead;
	while ((bytesRead = fread(buffer, 1, sizeof(buffer), inputFile)) > 0) {
		fwrite(buffer, 1, bytesRead, tempFilePtr);
	}
	
	fclose(inputFile);
	fclose(tempFilePtr);
	
	// Calculer le hash SHA-256 en utilisant sha256sum
	char command[1024];
	snprintf(command, sizeof(command), "sha256sum %s | awk '{print $1}'", tempFileName);
	FILE* pipe = popen(command, "r");
	if (!pipe) {
		perror("Erreur lors de l'exécution de la commande sha256sum");
		exit(EXIT_FAILURE);
	}
	
	char result[65]; // 64 caractères pour le hash SHA-256 + 1 caractère pour le caractère nul
	fgets(result, sizeof(result), pipe);
	
	// Fermer le pipe
	pclose(pipe);
	
	// Supprimer le fichier temporaire
	remove(tempFileName);
	
	// Allouer de la mémoire pour stocker le résultat
	char* hash = strdup(result);
	if (!hash) {
		perror("Erreur lors de l'allocation de mémoire");
		exit(EXIT_FAILURE);
	}
	
	// Retourner le hash SHA-256
	return hash;
}

void print_errors(const char *function, const char *file, int line) {
	ERR_print_errors_fp(stderr); // Only stderr as the argument
	fprintf(stderr, "Error at %s:%d in %s\n", file, line, function);
}

int hash_file(const char* source, char* dest) {
	EVP_MD_CTX* ctx = EVP_MD_CTX_create();
	const EVP_MD* digest = EVP_get_digestbyname("sha256");
	FILE* file = fopen(source, "rb");
	unsigned char buffer[1024];
	unsigned char hash[EVP_MAX_MD_SIZE];
	unsigned int hash_len;
	
	if (!ctx || !digest || !file) {
		print_errors("EVP_MD_CTX_create, EVP_get_digestbyname, or fopen", __FILE__, __LINE__);
		return 1;
	}
	
	if (!EVP_DigestInit_ex(ctx, digest, NULL)) {
		print_errors("EVP_DigestInit_ex", __FILE__, __LINE__);
		return 1;
	}
	
	while (1) {
		size_t bytes_read = fread(buffer, 1, sizeof(buffer), file);
		if (bytes_read == 0) {
			break; // EOF
		}
		if (!EVP_DigestUpdate(ctx, buffer, bytes_read)) {
			print_errors("EVP_DigestUpdate", __FILE__, __LINE__);
			return 1;
		}
	}
	
	if (!EVP_DigestFinal_ex(ctx, hash, &hash_len)) {
		print_errors("EVP_DigestFinal_ex", __FILE__, __LINE__);
		return 1;
	}
	
	fclose(file);
	EVP_MD_CTX_destroy(ctx);
	
	// Output hash to dest file in hexadecimal format
	FILE* output_file = fopen(dest, "w");
	if (!output_file) {
		perror("fopen dest");
		return 1;
	}
	for (unsigned int i = 0; i < hash_len; i++) {
		fprintf(output_file, "%02x", hash[i]);
	}
	fclose(output_file);
	
	return 0;
}
typedef struct cell {
	char* data;
	struct cell* next;
} Cell;
typedef Cell* List;
List* initList() {
	List* newList = malloc(sizeof(List));
	if (newList == NULL) {
		fprintf(stderr, "Erreur d'allocation mémoire\n");
		exit(EXIT_FAILURE);
	}
	*newList = NULL; // Initialiser la liste vide
	return newList;
}
Cell* buildCell(char* ch) {
	// Allouer de la mémoire pour la nouvelle cellule
	Cell* newCell = malloc(sizeof(Cell));
	if (newCell == NULL) {
		fprintf(stderr, "Erreur d'allocation mémoire\n");
		exit(EXIT_FAILURE);
	}
	
	// Allouer de la mémoire pour copier la chaîne de caractères
	newCell->data = strdup(ch);
	if (newCell->data == NULL) {
		fprintf(stderr, "Erreur d'allocation mémoire\n");
		exit(EXIT_FAILURE);
	}
	
	// Initialiser le pointeur suivant à NULL
	newCell->next = NULL;
	
	// Retourner la nouvelle cellule
	return newCell;
}
void insertFirst(List *L, Cell* C) {
	// Si la liste est vide, assigner la cellule en tant que tête de liste
	if (*L == NULL) {
		*L = C;
	} else {
		// Sinon, mettre la cellule en tête de liste et ajuster les pointeurs
		C->next = *L;
		*L = C;
	}}



char* ctos(Cell* c) {
	if (c == NULL) {
		return NULL;
	}
	return c->data;
}
char* ltos(List* L) {
	if (*L == NULL) {
		return NULL;
	}
	
	// Calcul de la longueur totale de la chaîne
	size_t totalLength = 0;
	Cell* current = *L;
	while (current != NULL) {
		totalLength += strlen(current->data) + 1; // +1 pour le séparateur '|'
		current = current->next;
	}
	
	// Allouer de la mémoire pour la chaîne résultante
	char* result = malloc(totalLength + 1); // +1 pour le caractère nul
	if (result == NULL) {
		fprintf(stderr, "Erreur d'allocation mémoire\n");
		exit(EXIT_FAILURE);
	}
	
	// Construire la chaîne résultante en parcourant la liste
	current = *L;
	size_t index = 0;
	while (current != NULL) {
		size_t len = strlen(current->data);
		strncpy(result + index, current->data, len);
		index += len;
		result[index++] = '|'; // Ajouter le séparateur '|'
		current = current->next;
	}
	result[index - 1] = '\0'; // Remplacer le dernier '|' par le caractère nul
	
	return result;
}
Cell* listGet(List* L, int i) {
	if (*L == NULL || i < 0) {
		return NULL; // Si la liste est vide ou si l'index est invalide, retourner NULL
	}
	
	Cell* current = *L;
	int index = 0;
	
	// Parcourir la liste jusqu'à l'élément désiré
	while (current != NULL && index < i) {
		current = current->next;
		index++;
	}
	
	// Si l'index est supérieur à la taille de la liste, retourner NULL
	if (index != i || current == NULL) {
		return NULL;
	}
	
	// Sinon, retourner l'élément trouvé
	return current;
}
Cell* searchList(List* L, char* str) {
	if (*L == NULL || str == NULL) {
		return NULL; // Si la liste est vide ou si la chaîne est NULL, retourner NULL
	}
	
	Cell* current = *L;
	
	// Parcourir la liste
	while (current != NULL) {
		// Comparer le contenu de la cellule avec la chaîne donnée
		if (strcmp(current->data, str) == 0) {
			return current; // Si la chaîne est trouvée, retourner la cellule
		}
		current = current->next;
	}
	
	// Si la chaîne n'est pas trouvée dans la liste, retourner NULL
	return NULL;
}
List* stol(char* s) {
	List* head = initList(); // Initialiser la liste
	
	char* token = strtok(s, "|"); // Utiliser '|' comme délimiteur
	while (token != NULL) {
		Cell* new_cell = buildCell(token); // Créer une nouvelle cellule avec le token
		insertFirst(head, new_cell); // Insérer la nouvelle cellule en tête de liste
		token = strtok(NULL, "|"); // Passage au token suivant
	}
	
	return head; // Retourner la tête de liste
}
void ltof(List* L, char* path) {
	FILE* file = fopen(path, "w");
	if (file == NULL) {
		fprintf(stderr, "Erreur lors de l'ouverture du fichier %s\n", path);
		exit(EXIT_FAILURE);
	}
	
	Cell* current = *L;
	while (current != NULL) {
		fprintf(file, "%s|", current->data);
		current = current->next;
	}
	
	fclose(file);
}

List* ftol(char* path) {
	FILE* file = fopen(path, "r");
	if (file == NULL) {
		fprintf(stderr, "Erreur lors de l'ouverture du fichier %s\n", path);
		exit(EXIT_FAILURE);
	}
	
	List* newList = malloc(sizeof(List));
	if (newList == NULL) {
		fprintf(stderr, "Erreur d'allocation mémoire\n");
		exit(EXIT_FAILURE);
	}
	*newList = NULL;
	
	char buffer[256];
	while (fgets(buffer, sizeof(buffer), file) != NULL) {
		char* token = strtok(buffer, "|");
		while (token != NULL) {
			Cell* newCell = malloc(sizeof(Cell));
			if (newCell == NULL) {
				fprintf(stderr, "Erreur d'allocation mémoire\n");
				exit(EXIT_FAILURE);
			}
			newCell->data = strdup(token);
			newCell->next = *newList;
			*newList = newCell;
			token = strtok(NULL, "|");
		}
	}
	
	fclose(file);
	return newList;
}
List* listdir(char* root_dir) {
	DIR* dp = opendir(root_dir);
	if (dp == NULL) {
		perror("Erreur lors de l'ouverture du répertoire");
		exit(EXIT_FAILURE);
	}
	
	List* fileList = initList(); // Initialisation de la liste vide
	struct dirent* entry;
	
	while ((entry = readdir(dp)) != NULL) {
		// Création d'une nouvelle cellule avec le nom du fichier/dossier
		Cell* newCell = buildCell(entry->d_name);
		// Insertion de la cellule en tête de liste
		insertFirst(fileList, newCell);
	}
	
	closedir(dp);
	return fileList;
}
int file_exists(char *file) {
	// Obtention de la liste des fichiers dans le répertoire courant
	List* fileList = listdir(".");
	Cell* current = *fileList;
	
	// Parcours de la liste pour vérifier si le fichier existe
	while (current != NULL) {
		if (strcmp(current->data, file) == 0) {
			// Le fichier a été trouvé dans le répertoire courant
			// Libération de la mémoire allouée pour la liste et ses éléments
			while (*fileList != NULL) {
				Cell* temp = *fileList;
				*fileList = (*fileList)->next;
				free(temp->data); // Libération de la mémoire allouée pour la chaîne de caractères
				free(temp);       // Libération de la mémoire allouée pour la cellule
			}
			free(fileList);
			return 1; // Le fichier existe
		}
		current = current->next;
	}
	
	// Libération de la mémoire allouée pour la liste et ses éléments
	while (*fileList != NULL) {
		Cell* temp = *fileList;
		*fileList = (*fileList)->next;
		free(temp->data); // Libération de la mémoire allouée pour la chaîne de caractères
		free(temp);       // Libération de la mémoire allouée pour la cellule
	}
	free(fileList);
	
	// Le fichier n'a pas été trouvé dans le répertoire courant
	return 0;
}
void cp(char *to, char *from) {
	// Ouvrir le fichier source en lecture
	FILE *source = fopen(from, "r");
	if (source == NULL) {
		fprintf(stderr, "Erreur : Impossible d'ouvrir le fichier source %s\n", from);
		return;
	}
	
	// Ouvrir le fichier destination en écriture
	FILE *destination = fopen(to, "w");
	if (destination == NULL) {
		fprintf(stderr, "Erreur : Impossible d'ouvrir le fichier destination %s\n", to);
		fclose(source);
		return;
	}
	
	// Copie ligne par ligne
	char buffer[1024];
	while (fgets(buffer, sizeof(buffer), source) != NULL) {
		fputs(buffer, destination);
	}
	
	// Fermer les fichiers
	fclose(source);
	fclose(destination);
	
	printf("Copie du fichier terminée avec succès.\n");
}
char* hashToPath(char* hash) {
	// Vérifier si le hash est valide (de longueur au moins 3)
	if (strlen(hash) < 3) {
		printf("Erreur : Hash invalide.\n");
		return NULL;
	}
	
	// Allouer de la mémoire pour le chemin résultant
	char* path = (char*)malloc((strlen(hash) + 2) * sizeof(char)); // +2 pour le '/' et le caractère nul
	
	// Construire le chemin en insérant '/' entre le deuxième et le troisième caractères du hash
	strncpy(path, hash, 2); // Copier les deux premiers caractères
	path[2] = '/'; // Insérer '/'
	strncpy(path + 3, hash + 2, strlen(hash) - 2); // Copier le reste du hash
	path[strlen(hash) + 1] = '\0'; // Ajouter le caractère nul à la fin
	
	return path;
}
void blobFile(char* file) {
	char command[512]; // Chaîne pour stocker la commande shell
	char dirname[512]; // Nom du répertoire de destination
	
	// Vérifier si le fichier existe
	FILE *fp = fopen(file, "r");
	if (fp == NULL) {
		printf("Erreur : Le fichier %s n'existe pas.\n", file);
		return;
	}
	fclose(fp);
	
	// Créer un répertoire "snapshots" s'il n'existe pas déjà
	if (system("[ -d snapshots ] || mkdir snapshots") != 0) {
		printf("Erreur lors de la création du répertoire snapshots.\n");
		return;
	}
	
	// Obtenir le nom du fichier sans le chemin
	char *filename = strrchr(file, '/');
	if (filename == NULL) // Pas de slash, donc le nom du fichier est le nom complet
		filename = file;
	else // Si le nom du fichier contient un slash, on prend la partie après le dernier slash
		filename++;
	
	// Construire le nom du répertoire de destination
	sprintf(dirname, "snapshots/%s_snapshot_$(date +%%Y%%m%%d_%%H%%M%%S)", filename);
	
	// Créer le répertoire de destination
	sprintf(command, "mkdir -p \"%s\"", dirname);
	if (system(command) != 0) {
		printf("Erreur lors de la création du répertoire de destination.\n");
		return;
	}
	
	// Construire la commande pour copier le fichier dans le répertoire snapshots
	sprintf(command, "cp \"%s\" \"%s/%s\"", file, dirname, filename);
	
	// Exécuter la commande shell
	if (system(command) != 0) {
		printf("Erreur lors de la copie du fichier %s.\n", file);
		return;
	}
	
	printf("Instantané du fichier %s enregistré.\n", file);
}
//partie 2 
typedef struct {
	char* name;
	char* hash;
	int mode;
} WorkFile;
typedef struct {
	WorkFile* tab;
	int size;
	int n;
} WorkTree;
int getChmod(const char *path){
	struct stat ret;
	if (stat(path, &ret) == -1) {
		return -1;
	}
	return
	(ret.st_mode & S_IRUSR)|(ret.st_mode & S_IWUSR)|(ret.st_mode & S_IXUSR)|/*owner*/
	(ret.st_mode & S_IRGRP)|(ret.st_mode & S_IWGRP)|(ret.st_mode & S_IXGRP)|/*group*/
	(ret.st_mode & S_IROTH)|(ret.st_mode & S_IWOTH)|(ret.st_mode & S_IXOTH);/*other*/
}
void setMode(int mode, char* path){
	char buff [100];
	sprintf(buff,"chmod %d %s", mode, path);
	system(buff);
}
WorkFile* createWorkFile(char* name) {
	WorkFile* wf = (WorkFile*) malloc(sizeof(WorkFile));
	if (wf == NULL) {
		fprintf(stderr, "Memory allocation error\n");
		return NULL;
	}
	wf->name = strdup(name); // Assurez-vous d'inclure <string.h> pour strdup
	if (wf->name == NULL) {
		fprintf(stderr, "Memory allocation error for name\n");
		free(wf);
		return NULL;
	}
	wf->hash = NULL;
	wf->mode = 0;
	return wf;
}
void freeWorkFile(WorkFile* wf) {
	if (wf != NULL) {
		free(wf->name);
		free(wf->hash);
		free(wf);
	}
}

char* wfts(WorkFile* wf) {
	if (wf == NULL) {
		return NULL;
	}
	
	// Calcul de la taille de la chaîne résultante
	int size = strlen(wf->name) + 1; // Pour le nom et le '\t'
	if (wf->hash != NULL) {
		size += strlen(wf->hash) + 1; // Pour le hash et le '\t'
	} else {
		size += 1; // Pour '\t' même si hash est NULL
	}
	size += 10; // Pour le mode (nombre maximum de chiffres pour int) et le '\0'
	
	// Allocation de la chaîne résultante
	char* result = (char*) malloc(size * sizeof(char));
	if (result == NULL) {
		fprintf(stderr, "Memory allocation error\n");
		return NULL;
	}
	
	// Construction de la chaîne résultante
	if (wf->hash != NULL) {
		snprintf(result, size, "%s\t%s\t%d", wf->name, wf->hash, wf->mode);
	} else {
		snprintf(result, size, "%s\t\t%d", wf->name, wf->mode); // Hash manquant
	}
	
	return result;
}
WorkFile* stwf(char* ch) {
	if (ch == NULL) {
		return NULL;
	}
	
	// Duplicate the input string to avoid modifying the original string
	char* input = strdup(ch);
	if (input == NULL) {
		fprintf(stderr, "Memory allocation error\n");
		return NULL;
	}
	
	// Split the input string by tabs
	char* name = strtok(input, "\t");
	char* hash = strtok(NULL, "\t");
	char* mode_str = strtok(NULL, "\t");
	
	if (name == NULL || mode_str == NULL) {
		free(input);
		return NULL;
	}
	
	// Create a new WorkFile
	WorkFile* wf = (WorkFile*) malloc(sizeof(WorkFile));
	if (wf == NULL) {
		fprintf(stderr, "Memory allocation error\n");
		free(input);
		return NULL;
	}
	
	// Initialize the WorkFile fields
	wf->name = strdup(name);
	if (wf->name == NULL) {
		fprintf(stderr, "Memory allocation error for name\n");
		free(wf);
		free(input);
		return NULL;
	}
	
	if (hash != NULL && strlen(hash) > 0) {
		wf->hash = strdup(hash);
		if (wf->hash == NULL) {
			fprintf(stderr, "Memory allocation error for hash\n");
			free(wf->name);
			free(wf);
			free(input);
			return NULL;
		}
	} else {
		wf->hash = NULL;
	}
	
	wf->mode = atoi(mode_str);
	
	// Free the duplicated input string
	free(input);
	
	return wf;
}
#define WORKTREE_SIZE 100 
WorkTree* initWorkTree() {
	// Allocation mémoire pour le WorkTree
	WorkTree* wt = (WorkTree*) malloc(sizeof(WorkTree));
	if (wt == NULL) {
		fprintf(stderr, "Memory allocation error\n");
		return NULL;
	}
	
	// Allocation mémoire pour le tableau de WorkFile
	wt->tab = (WorkFile*) malloc(WORKTREE_SIZE * sizeof(WorkFile));
	if (wt->tab == NULL) {
		fprintf(stderr, "Memory allocation error for WorkFile array\n");
		free(wt);
		return NULL;
	}
	
	// Initialisation des champs du WorkTree
	wt->size = WORKTREE_SIZE;
	wt->n = 0;
	
	return wt;
}
void freeWorkTree(WorkTree* wt) {
	if (wt != NULL) {
		for (int i = 0; i < wt->n; i++) {
			freeWorkFile(&wt->tab[i]);
		}
		free(wt->tab);
		free(wt);
	}
}
int inWorkTree(WorkTree* wt, char* name) {
	if (wt == NULL || name == NULL) {
		return -1;
	}
	
	for (int i = 0; i < wt->n; i++) {
		if (strcmp(wt->tab[i].name, name) == 0) {
			return i;
		}
	}
	
	return -1;
}
int appendWorkTree(WorkTree* wt, char* name, char* hash, int mode) {
	if (wt == NULL || name == NULL || hash == NULL) {
		return -1;
	}
	
	if (inWorkTree(wt, name) != -1) {
		// Le fichier ou répertoire existe déjà
		return -1;
	}
	
	if (wt->n >= wt->size) {
		// Le WorkTree est plein
		return -1;
	}
	
	WorkFile* wf = createWorkFile(name);
	if (wf == NULL) {
		return -1;
	}
	
	wf->hash = strdup(hash);

	
	wf->mode = mode;
	wt->tab[wt->n++] = *wf;
	free(wf); // Free the temporary WorkFile structure but not the strings inside it
	
	return 0;
}
char* wtts(WorkTree* wt) {
	// Calculate the required buffer size
	size_t buffer_size = 0;
	for (int i = 0; i < wt->n; i++) {
		buffer_size += strlen(wt->tab[i].name) + strlen(wt->tab[i].hash) + 20; // 20 for mode and delimiters
	}
	
	// Allocate the buffer
	char* buffer = (char*)malloc(buffer_size + 1);
	if (!buffer) {
		perror("malloc");
		exit(EXIT_FAILURE);
	}
	buffer[0] = '\0'; // Initialize as empty string
	
	// Concatenate each WorkFile's string representation to the buffer
	for (int i = 0; i < wt->n; i++) {
		char* wf_str = wfts(&wt->tab[i]);
		strcat(buffer, wf_str);
		strcat(buffer, "\n");
		free(wf_str);
	}
	
	return buffer;
}
WorkTree* stwt(char* ch) {
	if (ch == NULL) {
		return NULL;
	}
	
	WorkTree* wt = initWorkTree();
	if (wt == NULL) {
		return NULL;
	}
	
	char* line = strtok(ch, "\n");
	while (line != NULL) {
		WorkFile* wf = stwf(line);


		wt->tab[wt->n++] = *wf;
		free(wf);
		line = strtok(NULL, "\n");
	}
	
	return wt;
}
int wttf(WorkTree* wt, char* file) {
	if (wt == NULL || file == NULL) {
		return -1;
	}
	
	FILE* fp = fopen(file, "w");
	if (fp == NULL) {
		fprintf(stderr, "Error opening file %s\n", file);
		return -1;
	}
	
	char* serialized_wt = wtts(wt);
	if (serialized_wt == NULL) {
		fclose(fp);
		return -1;
	}
	
	fprintf(fp, "%s", serialized_wt);
	
	fclose(fp);
	free(serialized_wt);
	
	return 0;
}
WorkTree* ftwt(const char* file_path) {
	FILE* file = fopen(file_path, "r");
	if (!file) {
		perror("fopen");
		return NULL;
	}
	
	WorkTree* wt = initWorkTree();
	if (!wt) {
		fclose(file);
		return NULL;
	}
	
	char line[256];  // Buffer to hold each line read from the file
	while (fgets(line, sizeof(line), file)) {
		// Removing newline character if present
		size_t len = strlen(line);
		if (len > 0 && line[len - 1] == '\n') {
			line[len - 1] = '\0';
		}
		
		WorkFile* wf = stwf(line);
		if (wf) {
			if (appendWorkTree(wt, wf->name, wf->hash, wf->mode) == -1) {
				printf("Error: Could not append WorkFile to WorkTree.\n");
				freeWorkFile(wf);
				freeWorkTree(wt);
				fclose(file);
				return NULL;
			}
			freeWorkFile(wf); // free the temporary WorkFile
		} else {
			printf("Error: Could not convert string to WorkFile.\n");
			freeWorkTree(wt);
			fclose(file);
			return NULL;
		}
	}
	
	fclose(file);
	return wt;
}
#define MAX_PATH_LENGTH 1024
WorkTree* listdir1(char* dir_path) {
	DIR* dir = opendir(dir_path);
	if (dir == NULL) {
		perror("Error opening directory");
		return NULL;
	}
	
	WorkTree* wt = initWorkTree();
	if (wt == NULL) {
		closedir(dir);
		return NULL;
	}
	
	struct dirent* entry;
	while ((entry = readdir(dir)) != NULL) {
		// Ignore "." and ".."
		if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
			continue;
		}
		
		// Build full path
		char entry_path[MAX_PATH_LENGTH];
		snprintf(entry_path, MAX_PATH_LENGTH, "%s/%s", dir_path, entry->d_name);
		
		struct stat st;
		if (stat(entry_path, &st) == -1) {
			perror("Error getting file info");
			continue;
		}
		
		if (S_ISREG(st.st_mode)) {
			// File
			if (appendWorkTree(wt, entry_path, NULL, st.st_mode) == -1) {
				perror("Error appending file to WorkTree");
				freeWorkTree(wt);
				closedir(dir);
				return NULL;
			}
		} else if (S_ISDIR(st.st_mode)) {
			// Directory
			WorkTree* subtree = listdir1(entry_path);
			if (subtree == NULL) {
				closedir(dir);
				return NULL;
			}
			
			if (appendWorkTree(wt, entry_path, NULL, st.st_mode) == -1) {
				perror("Error appending directory to WorkTree");
				freeWorkTree(wt);
				freeWorkTree(subtree);
				closedir(dir);
				return NULL;
			}
			
			for (int i = 0; i < subtree->n; i++) {
				WorkFile* subfile = &subtree->tab[i];
				char* subfile_path = subfile->name + strlen(dir_path) + 1;
				if (appendWorkTree(wt, subfile_path, subfile->hash, subfile->mode) == -1) {
					perror("Error appending subfile to WorkTree");
					freeWorkTree(wt);
					freeWorkTree(subtree);
					closedir(dir);
					return NULL;
				}
			}
			freeWorkTree(subtree);
		} else {
			// Other type of file (e.g., symlink, socket, etc.)
			printf("Skipping file '%s' with unsupported type\n", entry_path);
		}
	}
	
	closedir(dir);
	return wt;
}
char* blobFile1(char* file_path) {
	FILE* file = fopen(file_path, "rb");
	if (file == NULL) {
		perror("Error opening file");
		return NULL;
	}
	
	// Créer un tampon pour stocker les données lues
	unsigned char buffer[BUFFER_SIZE];
	SHA_CTX ctx;
	SHA1_Init(&ctx);
	
	// Lire le contenu du fichier par blocs et mettre à jour le hash
	size_t bytes_read;
	while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, file)) > 0) {
		SHA1_Update(&ctx, buffer, bytes_read);
	}
	
	// Finaliser le hash
	unsigned char hash[SHA_DIGEST_LENGTH];
	SHA1_Final(hash, &ctx);
	
	// Convertir le hash en une chaîne hexadécimale
	char* hash_str = (char*)malloc((SHA_DIGEST_LENGTH * 2 + 1) * sizeof(char));
	if (hash_str == NULL) {
		fclose(file);
		perror("Memory allocation error");
		return NULL;
	}
	for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
		sprintf(&hash_str[i * 2], "%02x", hash[i]);
	}
	hash_str[SHA_DIGEST_LENGTH * 2] = '\0';
	
	fclose(file);
	return hash_str;
}

char* blobWorkTree(WorkTree* wt) {
	if (wt == NULL)
		return NULL;
	
	// Créer un fichier temporaire pour stocker la représentation du WorkTree
	char temp_path[] = "/tmp/worktree_tempXXXXXX";
	int temp_fd = mkstemp(temp_path);
	if (temp_fd == -1) {
		perror("Error creating temporary file");
		return NULL;
	}
	
	// Écrire la représentation du WorkTree dans le fichier temporaire
	char* tree_string = wtts(wt);
	if (tree_string == NULL) {
		close(temp_fd);
		unlink(temp_path);
		return NULL;
	}
	ssize_t write_size = write(temp_fd, tree_string, strlen(tree_string));
	free(tree_string);
	close(temp_fd);
	
	if (write_size == -1) {
		perror("Error writing to temporary file");
		unlink(temp_path);
		return NULL;
	}
	
	// Calculer le hash du fichier temporaire
	// (Ici, je suppose que vous avez une fonction pour calculer le hash d'un fichier)
	char* tree_hash = sha256file(temp_path);
	
	// Supprimer le fichier temporaire
	unlink(temp_path);
	
	return tree_hash;
}
char* saveWorkTree(WorkTree* wt, char* path) {
	if (wt == NULL || path == NULL)
		return NULL;
	
	for (int i = 0; i < wt->n; i++) {
		WorkFile* wf = &wt->tab[i];
		if (S_ISDIR(wf->mode)) {
			// Répertoire, traitement récursif
			WorkTree* subtree = listdir1(wf->name);
			if (subtree == NULL)
				return NULL;
			
			char* subtree_hash = saveWorkTree(subtree, wf->name);


			
			// Mettre à jour le hash et le mode
			free(wf->hash);
			wf->hash = strdup(subtree_hash);
			wf->mode = S_IFDIR | 0755; // Exemple : mode de répertoire
		} else {
			// Fichier, traitement blobFile
			char* file_hash = blobFile1(wf->name);
			if (file_hash == NULL)
				return NULL;
			
			// Mettre à jour le hash et le mode
			free(wf->hash);
			wf->hash = strdup(file_hash);
			wf->mode = S_IFREG | 0644; // Exemple : mode de fichier
		}
	}
	
	// Créer l'enregistrement instantané du WorkTree principal
	char* tree_hash = blobWorkTree(wt);
	if (tree_hash == NULL)
		return NULL;
	
	return tree_hash;
}
int copyFile(char* src_path, char* dest_dir, char* filename, int mode) {
	// Créer le chemin complet de destination
	char dest_path[MAX_PATH_LENGTH];
	snprintf(dest_path, MAX_PATH_LENGTH, "%s/%s", dest_dir, filename);
	
	// Ouvrir le fichier source en lecture
	FILE* src_file = fopen(src_path, "rb");
	if (src_file == NULL) {
		perror("Error opening source file");
		return -1;
	}
	
	// Ouvrir le fichier destination en écriture
	FILE* dest_file = fopen(dest_path, "wb");
	if (dest_file == NULL) {
		perror("Error opening destination file");
		fclose(src_file);
		return -1;
	}
	
	// Copier le contenu du fichier source vers le fichier destination
	char buffer[BUFFER_SIZE];
	size_t bytes_read;
	while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, src_file)) > 0) {
		size_t bytes_written = fwrite(buffer, 1, bytes_read, dest_file);
		if (bytes_written < bytes_read) {
			perror("Error writing to destination file");
			fclose(src_file);
			fclose(dest_file);
			return -1;
		}
	}
	
	// Fermer les fichiers
	fclose(src_file);
	fclose(dest_file);
	
	// Changer les autorisations du fichier destination
	if (chmod(dest_path, mode) == -1) {
		perror("Error changing permissions of destination file");
		return -1;
	}
	
	return 0;
}
#define MAX_PATH_LENGTH 1024

char* findSnapshotPath(char* hash) {
	// Chemin du répertoire contenant les enregistrements instantanés
	char* snapshot_dir = "/home/helmi/Documents/snapshots";
	
	DIR* dir = opendir(snapshot_dir);
	if (dir == NULL) {
		perror("Error opening snapshot directory");
		return NULL;
	}
	
	struct dirent* entry;
	while ((entry = readdir(dir)) != NULL) {
		// Ignorer les entrées "." et ".."
		if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
			continue;
		}
		
		// Vérifier si le nom du fichier correspond au hash
		if (strcmp(entry->d_name, hash) == 0) {
			// Construire le chemin complet de l'enregistrement instantané
			char* snapshot_path = (char*)malloc((strlen(snapshot_dir) + strlen(entry->d_name) + 2) * sizeof(char));
			if (snapshot_path == NULL) {
				perror("Memory allocation error");
				closedir(dir);
				return NULL;
			}
			snprintf(snapshot_path, MAX_PATH_LENGTH, "%s/%s", snapshot_dir, entry->d_name);
			
			closedir(dir);
			return snapshot_path;
		}
	}
	
	closedir(dir);
	printf("Snapshot not found for hash: %s\n", hash);
	return NULL;
}
void restoreWorkTree(WorkTree* wt, char* snapshot_dir, char* path) {
	if (wt == NULL || snapshot_dir == NULL || path == NULL)
		return;
	
	for (int i = 0; i < wt->n; i++) {
		WorkFile* wf = &wt->tab[i];
		if (wf->hash == NULL)
			continue; // Skip if hash is not present
		
		// Trouver l'enregistrement instantané correspondant au hash de WF
		char* snapshot_path = findSnapshotPath(wf->hash);
		if (snapshot_path == NULL)
			return; // Snapshot not found
		
		// Si l'enregistrement ne possède pas l'extension ".t", il s'agit d'un fichier
		if (strcmp(snapshot_path + strlen(snapshot_path) - 2, ".t") != 0) {
			// Créer une copie de l'enregistrement à l'emplacement spécifié par path
			if (copyFile(snapshot_path, path, wf->name, wf->mode) == -1)
				return; // Error copying file
		} else {
			// Sinon, il s'agit d'un répertoire
			// Modifier la variable path en y ajoutant ce répertoire à la fin
			strcat(path, "/");
			strcat(path, wf->name);
			
			// Créer le répertoire correspondant dans le chemin spécifié
			if (mkdir(path, wf->mode) != 0) {
				perror("Error creating directory");
				return;
			}
			
			// Faire un appel récursif sur ce nouveau répertoire
			restoreWorkTree(snapshot_path, snapshot_dir, path);
			
			// Réinitialiser le chemin pour le répertoire parent
			path[strlen(path) - strlen(wf->name) - 1] = '\0'; // Supprimer le nom du répertoire ajouté
		}
	}
	strcat(path, "/restored");
}

// Fonction pour créer un enregistrement instantané du WorkTree et retourner son hash


int main() {
	system("ls");
	int result = hash_file("/home/helmi/projetscv/main.c", "/home/helmi/projetscv/main.tmp");
	if (result != 0) {
		fprintf(stderr, "Error: Hashing failed\n");
		
	}
	printf("Hashing successful!\n");
	
	
	char *hash = sha256file("/home/helmi/projetscv/main1.c");
	printf("proceed with hash");
	
	if (hash != NULL) {
		
		printf("Hash: %s\n", hash);
		free(hash); // Remember to free the allocated memory after use
		
	} else {
		fprintf(stderr, "Error: Could not calculate hash\n");
	}
// Initialisation de la liste vide
	List* maliste = initList();
	
	// Ajout d'un élément à la liste
	Cell* newCell = malloc(sizeof(Cell));
	if (newCell == NULL) {
		fprintf(stderr, "Erreur d'allocation mémoire\n");
		exit(EXIT_FAILURE);
	}
	newCell->data = "Premier élément";
	newCell->next = NULL;
	
	// Liaison du nouvel élément à la liste
	insertFirst(maliste, newCell);
	
	// Parcours de la liste et affichage des éléments
	Cell* current = *maliste;
	while (current != NULL) {
		printf("%s\n", current->data);
		current = current->next;
	}
	
	// Libération de la mémoire allouée pour la liste et ses éléments
	current = *maliste;
	while (current != NULL) {
		Cell* temp = current;
		current = current->next;
		free(temp);
	}
	free(maliste);
	char* myString = "test 1";
	Cell* myCell = buildCell(myString);
	
	// Affichage du contenu de la cellule
	printf("Contenu de la cellule : %s\n", myCell->data);
	
	// Libération de la mémoire allouée pour la cellule
	free(myCell->data); // Libérer d'abord la chaîne de caractères allouée par strdup
	free(myCell);
	// Création de quelques cellules pour former une liste
	Cell cell1 = {"Donnée 1", NULL};
	Cell cell2 = {"Donnée 2", NULL};
	Cell cell3 = {"Donnée 3", NULL};
	
	// Initialisation d'un pointeur de liste pour pointer vers la tête de la liste
	List myList = NULL;
	
	// Insertion des cellules en tête de liste pour former la liste
	insertFirst(&myList, &cell3);
	insertFirst(&myList, &cell2);
	insertFirst(&myList, &cell1);
	
	// Utilisation de la fonction ltos pour convertir la liste en une chaîne de caractères
	char* resultat = ltos(&myList);
	
	// Affichage du résultat
	if (resultat != NULL) {
		printf("Résultat : %s\n", resultat);
		free(resultat); // Libérer la mémoire allouée pour le résultat
	} else {
		printf("La liste est vide.\n");
	}
	int indexToRetrieve = 2;
	Cell* retrievedCell = listGet(&myList, indexToRetrieve);
	
	if (retrievedCell != NULL) {
		printf("L'élément à l'index %d est : %s\n", indexToRetrieve, retrievedCell->data);
	} else {
		printf("L'élément à l'index %d n'existe pas dans la liste.\n", indexToRetrieve);
	}
	char* strToFind = "Donnée 1";
	Cell* foundCell = searchList(&myList, strToFind);
	
	if (foundCell != NULL) {
		printf("L'élément \"%s\" a été trouvé dans la liste.\n", strToFind);
	} else {
		printf("L'élément \"%s\" n'a pas été trouvé dans la liste.\n", strToFind);
	}
	char s[] = "1|2|3|4|5"; // Chaîne représentant la liste d'entiers
	List* myList5 = stol(s); // Convertir la chaîne en liste chaînée
	
	// Parcourir la liste et afficher ses éléments
	Cell* courant = *myList5;
	while (courant != NULL) {
		printf("%s\n", courant->data);
		courant = courant->next;
	}
	
	// Libérer la mémoire allouée pour la liste
	courant = *myList5;
	while (courant != NULL) {
		Cell* temp = courant;
		courant = courant->next;
		free(temp);
	}
	free(myList5);
	List* newList6 = ftol("/home/helmi/projetscv/a");
	
	// Affichage de la liste lue
	Cell* current1 = *newList6;
	while (current1 != NULL) {
		printf("%s\n", current1->data);
		current1 = current1->next;
	}
	ltof(newList6,"/home/helmi/projetscv/b");
	List* fileList = listdir("/home/helmi/projetscv"); // chemin specifié
	
	printf("Contenu du répertoire :\n");
	Cell* current2 = *fileList;
	while (current2 != NULL) {
		printf("%s\n", current2->data);
		current2 = current2->next;
	}
	
	if (file_exists("abc")==1)
	{
		printf("le fichier existe\n");
	}
	else
	{
		printf("erreur");
	}
	cp("/home/helmi/projetscv/dest","/home/helmi/projetscv/source");
	char hash2[] = "a1b2c3d4e5f6";
	
	char* path = hashToPath(hash2);
	if (path != NULL) {
		printf("Chemin : %s\n", path);
		free(path); // Libérer la mémoire allouée pour le chemin
	}
	
	char filename3[] = "aac";
	blobFile(filename3);
	printf("-----partie 2--------\n");
	// Initialize WorkTree
	WorkTree* wt = initWorkTree();
	
	// Sample data: Files and directories
	char* file1_path = "/home/helmi/Documents/file1.txt";
	char* file1_hash = "hash1";
	int file1_mode = 0644;
	
	char* file2_path = "/home/helmi/Documents/file2.txt";
	char* file2_hash = "hash2";
	int file2_mode = 0644;
	
	char* dir1_path = "/home/helmi/Documents/dir1";
	char* dir1_hash = "hash3";
	int dir1_mode = 0755;
	char* file_path = "/home/helmi/Documents/test.txt";
	char* snapshot_dir = "/home/helmi/Documents/snapshots1";
	char* restore_dir = "/home/helmi/Documents/restored";
	// Add files to WorkTree
	appendWorkTree(wt, file1_path, file1_hash, file1_mode);
	appendWorkTree(wt, file2_path, file2_hash, file2_mode);
	
	// Create a new WorkTree for directory and add it to the WorkTree
	WorkTree* dir1_tree = initWorkTree();
	appendWorkTree(wt, dir1_path, dir1_hash, dir1_mode);
	
	// Add files to the directory WorkTree
	appendWorkTree(dir1_tree, file1_path, file1_hash, file1_mode);
	appendWorkTree(dir1_tree, file2_path, file2_hash, file2_mode);
	
	// Add the directory WorkTree to the main WorkTree
	appendWorkTree(wt, dir1_path, dir1_tree,0777);
	
	// Print WorkTree as string
	char* wt_string = wtts(wt);
	printf("WorkTree as string:\n%s\n", wt_string);
	free(wt_string);
	
	// Test other functions as per your requirement...
	char* blob_hash = blobWorkTree(wt);
	printf("Blob file hash: %s\n", blob_hash);
	free(blob_hash);
	
	// Step 3: Save WorkTree to a file
	char* save_hash = saveWorkTree(wt, snapshot_dir);
	printf("Snapshot saved with hash: %s\n", save_hash);
	free(save_hash);
	
	// Step 4: Restore WorkTree from snapshot
	restoreWorkTree(wt, snapshot_dir, restore_dir);
	printf("WorkTree restored successfully\n");
	
	// Step 5: Convert restored WorkTree to string
	char* restored_wt_string = wtts(wt);
	printf("Restored WorkTree as string:\n%s\n", restored_wt_string);
	free(restored_wt_string);
	
	// Clean up WorkTree


	//fichierss
	printf("_____________fichiers____________\n");
// Step 1: Create a WorkTree and populate it
	WorkTree* wt1 = initWorkTree();
	appendWorkTree(wt1, "file1.txt", "hash1", 0644);
	appendWorkTree(wt1, "file2.txt", "hash2", 0644);
	appendWorkTree(wt1, "dir1", "hash3", 0755);
	
	// Step 2: Save the WorkTree to a file
	char* wt_str = wtts(wt1);
	FILE* file = fopen("/home/helmi/Documents/cc", "w");
	if (file != NULL) {
		fprintf(file, "%s", wt_str);
		fclose(file);
	} else {
		printf("Error: Could not open file for writing.\n");
		free(wt_str);
		freeWorkTree(wt1);
		return 1;
	}

	// Step 3: Read the WorkTree representation from file
	char* file_path1 = "/home/helmi/Documents/cc";
	WorkTree* restored_wt = ftwt(file_path1);
	if (restored_wt == NULL) {
		printf("Error: Failed to restore WorkTree from file.\n");
		freeWorkTree(wt1);
		return 1;
	}

	// Step 4: Print the restored WorkTree
	char* restored_wt_str = wtts(restored_wt);
	printf("Restored WorkTree:\n%s", restored_wt_str);
	free(restored_wt_str);
	
	// Step 5: Clean up
	freeWorkTree(wt1);
	freeWorkTree(restored_wt);
	return 0;}

