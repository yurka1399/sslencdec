package sslencdec

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"strconv"
)

// EncoderDecoder Class
type EncoderDecoder struct {
	key []byte
}

// Init returns new EncoderDecoder object
func Init(bkey []byte) *EncoderDecoder {
	return &EncoderDecoder{
		key: bkey,
	}
}

// Encode given data using SSL
func (h *EncoderDecoder) Encode(toEncode []byte) ([]byte, error) {
	// получим строчку для енкода
	// получим iv
	iv := make([]byte, 16)
	_, err := rand.Read(iv)
	if err != nil {
		return nil, err
	}
	// шифруем
	block, err := aes.NewCipher(h.key)
	if err != nil {
		return nil, err
	}
	dataLen := []byte(fmt.Sprintf("%04d", len(toEncode)))
	encrypter := cipher.NewCFBEncrypter(block, iv)
	encrypted := make([]byte, len(toEncode))
	encrypter.XORKeyStream(encrypted, toEncode)
	// HMAC
	hmc := hmac.New(sha256.New, h.key)
	hmc.Write(encrypted)
	hm := hmc.Sum(nil)
	// соберем результат
	// кодируем длину образцовой строки
	res := append(iv, dataLen...)
	res = append(res, hm...)
	res = append(res, encrypted...)

	return res, nil
}

// Decode given data using SSL
func (h *EncoderDecoder) Decode(toDecode []byte) ([]byte, error) {
	// получаем iv
	iv := toDecode[:16]
	// получаем длину образцовой строки
	dataLen, err := strconv.Atoi(string(toDecode[16:20]))
	if err != nil {
		return nil, err
	}
	// HMAC
	hm := toDecode[20:52]
	// Дешифровка
	encrypted := toDecode[52:]
	// декрипт
	block, err := aes.NewCipher(h.key)
	decrypter := cipher.NewCFBDecrypter(block, iv)
	decrypted := make([]byte, dataLen)
	decrypter.XORKeyStream(decrypted, encrypted)
	// hmac для сравнения
	hmc := hmac.New(sha256.New, h.key)
	hmc.Write(encrypted)
	chm := hmc.Sum(nil)
	// если HMAC не совпадет - выход
	if !bytes.Equal(hm, chm) {
		return nil, errors.New("HMACs not equal")
	}
	return decrypted, nil
}
