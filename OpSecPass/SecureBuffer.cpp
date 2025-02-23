#include "SecureBuffer.h"

using namespace std;

// Initialisiert einen sicheren Buffer mit der angegeben Größe
SecureBuffer::SecureBuffer(size_t size) : data_(new vector<uint8_t>(size))
{
	
}

// Hebt den Memory-Lock auf und löscht den Inhalt , um sensible Daten zu entfernen
SecureBuffer::~SecureBuffer()
{
	sodium_munlock(data_->data(), data_->size());
	sodium_memzero(data_->data(), data_->size());
}

// Gibt einen Ptr auf den Speicherbuffer zurück
uint8_t* SecureBuffer::data()
{
	return data_->data();
}

// Gibt einen konstanten Zeiger auf den internen Speicherpuffer zurück (nur Lesezugriff)
const uint8_t* SecureBuffer::data() const {
	return data_->data();
}


// Liefert die Größe des Puffers in Bytes zurück
size_t SecureBuffer::size() const 
{
	return data_->size();
}

