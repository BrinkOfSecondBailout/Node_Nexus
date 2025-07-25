/* classifier.c */

#include "classifier.h"
#include <string.h>
#include <ctype.h>
#include <math.h>
#include <stdlib.h>


static struct {
	char word[MAX_WORD_LEN];
	double prob_positive;
	double prob_negative;
} vocabulary[] = {
	{"happy", 0.9, 0.1},
	{"good", 0.8, 0.2},
	{"great", 0.9, 0.1},
	{"bad", 0.2, 0.8},
	{"sad", 0.1, 0.9},
};

static const int vocab_size = sizeof(vocabulary) / sizeof(vocabulary[0]);
static const double prior_positive = 0.5;
static const double prior_negative = 0.5;

SentimentLabel classify_text(const char *text) {
	double log_prob_positive = log(prior_positive);
	double log_prob_negative = log(prior_negative);

	char *text_copy = strdup(text);
	char *token = strtok(text_copy, " ");
	while (token) {
		for (char *p = token; *p; p++) *p = tolower(*p);
		for (int i = 0; i < vocab_size; i++) {
			if (strcmp(token, vocabulary[i].word) == 0) {
				log_prob_positive += log(vocabulary[i].prob_positive);
				log_prob_negative += log(vocabulary[i].prob_negative);
				break;
			}
		}
		token = strtok(NULL, " ");
	}
	free(text_copy);
	free(token);
	return log_prob_positive > log_prob_negative ? POSITIVE : NEGATIVE;
}
