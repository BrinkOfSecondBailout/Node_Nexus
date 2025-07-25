/* classifier.h */

#ifndef CLASSIFIER_H
#define CLASSIFIER_H

#define MAX_VOCAB_SIZE 50
#define MAX_WORD_LEN 20

typedef enum {
	POSITIVE,
	NEGATIVE
} SentimentLabel;

SentimentLabel classify_text(const char *text);

#endif
