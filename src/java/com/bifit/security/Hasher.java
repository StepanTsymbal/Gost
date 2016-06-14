package com.bifit.security;

import java.math.BigInteger;

import javax.xml.bind.DatatypeConverter;

/**
 * Реализует процесс хеширования по ГОСТ 34.11-94
 *
 * @author Stepan Tsymbal
 */
public class Hasher {

    /**
     * Реализует полный цикл получения хеш-функции на основе массива байт.
     * Функционирует на основе{@link #hashPart(byte[], byte[])}
     *
     * @param bytes данные, для которых считается хеш-функция
     * @return массив байт - хеш-функция для входных данных
     */
    public static byte[] hash(byte[] bytes) {
        byte[] sum = new byte[32];
        byte[] hOut = new byte[32];
        byte[] lenTemp = BigInteger.valueOf(bytes.length * 8).toByteArray();
        byte[] leng = new byte[32];
        
        for (int i = 0; i < lenTemp.length; i++) {
            leng[31 - i] = lenTemp[lenTemp.length - i - 1];
        }
        byte[] hIn = new byte[32];
        byte[] mesPart = new byte[32];
        byte[] mesFull = new byte[((bytes.length / 32) * 32 + ((bytes.length % 32 != 0) ? 32 : 0))];
        System.arraycopy(bytes, 0, mesFull, 0, bytes.length);
        for (int i = 0; i < mesFull.length; i += 32) {
            for (int j = 0; j < 32; j++) {
                mesPart[j] = mesFull[i + j];
            }
            hashPart(mesPart, hIn);
            hOut = hashPart(mesPart, hIn);
            System.arraycopy(hOut, 0, hIn, 0, 32);
            for (int h = 0; h < 32; h++) {
                sum[31 - h] += mesPart[h];
            }
        }
        byte[] hPrelast = hashPart(leng, hOut);
        
        return hashPart(sum, hPrelast);
    }

    /**
     * Реализует полный цикл получения хеш-функции на основе входных данных типа String. Работает на основе
     * {@link #hashFull(byte[])}
     *
     * @param s данные, для которых считается хеш-функция
     * @return массив байт - хеш-функция для входных данных
     */
    public static byte[] hash(String s) {
        
        return hash(s.getBytes());
    }

    /**
     * Реализует один шаг процесса хеширования, используемый в {@link #hashFull(byte[])}
     *
     * @param m значение входного сообщения
     * @param hIn значение входной хеш-функции
     * @return массив преобразованных байт
     */
    private static byte[] hashPart(byte[] m, byte[] hIn) {
        byte[][] keys1 = keyGenerate(m, hIn);
        byte[] cipher1 = cipher(keys1, hIn);
        byte[] shuffle1 = shuffleFull(cipher1, hIn, m);
        
        return shuffle1;
    }

    /**
     * Реализует преобразование А(у)
     *
     * @param y данные для преобразования
     */
    private static void afterA(byte[] y) {
        byte a1, a2, a3, a4, a5, a6, a7, a8;
        
        a1 = (byte) (y[0] ^ y[8]);
        a2 = (byte) (y[1] ^ y[9]);
        a3 = (byte) (y[2] ^ y[10]);
        a4 = (byte) (y[3] ^ y[11]);
        a5 = (byte) (y[4] ^ y[12]);
        a6 = (byte) (y[5] ^ y[13]);
        a7 = (byte) (y[6] ^ y[14]);
        a8 = (byte) (y[7] ^ y[15]);
        for (int i = 0; i < 24; i++) {
            y[i] = y[i + 8];
        }
        y[24] = a1;
        y[25] = a2;
        y[26] = a3;
        y[27] = a4;
        y[28] = a5;
        y[29] = a6;
        y[30] = a7;
        y[31] = a8;
    }

    /**
     * Реализует преобразование P(у)
     *
     * @param y данные для преобразования
     * @return массив байт
     */
    private static byte[] afterP(byte[] y) {
        byte[] afterP = new byte[32];
        
        for (int i = 0; i <= 3; i++) {
            for (int k = 1; k <= 8; k++) {
                afterP[i + 1 + 4 * (k - 1) - 1] = y[8 * i + k - 1];
            }
        }
        
        return afterP;
    }

    /**
     * Генерирует ключи на основании входного сообщения m и хеш-функции hIn
     *
     * @param m входное сообщение
     * @param hIn входная хеш-функция
     * @return двумерный байт-массив ключей
     */
    private static byte[][] keyGenerate(byte[] m, byte[] hIn) {
        byte[] c2 = DatatypeConverter
                .parseHexBinary("0000000000000000000000000000000000000000000000000000000000000000");
        byte[] c4 = DatatypeConverter
                .parseHexBinary("0000000000000000000000000000000000000000000000000000000000000000");
        byte[] c3 = reverse(
                DatatypeConverter.parseHexBinary("ff00ffff000000ffff0000ff00ffff0000ff00ff00ff00ffff00ff00ff00ff00"));
        byte[] cTemp = null;
        byte[] kTemp = null;
        byte[] u = new byte[32];
        byte[] v = new byte[32];
        byte[] w = new byte[32];
        byte[][] k = new byte[4][];
        
        m = reverse(m);
        afterP(w);
        System.arraycopy(hIn, 0, u, 0, hIn.length);
        System.arraycopy(m, 0, v, 0, m.length);
        System.arraycopy(u, 0, w, 0, 32);
        sumXorArray(w, v);
        k[0] = afterP(w);
        for (int j = 0; j < 3; j++) {
            if (j == 0) {
                cTemp = c2;
            } else if (j == 1) {
                cTemp = c3;
            } else if (j == 2) {
                cTemp = c4;
            }
            afterA(u);
            sumXorArray(u, cTemp);
            afterA(v);
            afterA(v);
            System.arraycopy(u, 0, w, 0, 32);
            sumXorArray(w, v);
            kTemp = afterP(w);
            if (j == 0) {
                k[1] = kTemp;
            } else if (j == 1) {
                k[2] = kTemp;
            } else if (j == 2) {
                k[3] = kTemp;
            }
        }
        
        return k;
    }

    /**
     * Возвращает входной массив байт в обратном порядке
     *
     * @param a данные для реверсии
     * @return входной массив в обратном порядке
     */
    private static byte[] reverse(byte[] a) {
        for (int i = 0; i < a.length / 2; i++) {
            byte temp = a[i];
            a[i] = a[(a.length - 1) - i];
            a[(a.length - 1) - i] = temp;
        }
        
        return a;
    }

    /**
     * Шифрует входной массив байт hIn по ГОСТ 28147-89 с помощью ключей key
     *
     * @param key общий массив ключей
     * @param hIn данные для шифрования
     * @return массив зашифрованных байт
     */
    private static byte[] cipher(byte[][] key, byte[] hIn) {
        byte[] sT = new byte[32];
        byte[] h1 = new byte[8];
        byte[] h2 = new byte[8];
        byte[] h3 = new byte[8];
        byte[] h4 = new byte[8];
        
        Cipher encryptor = new Cipher();
        for (int i = 0; i < 8; i++) {
            h1[i] = hIn[i];
            h2[i] = hIn[i + 8];
            h3[i] = hIn[i + 16];
            h4[i] = hIn[i + 24];
        }
        System.arraycopy(encryptor.encrypt((h1), key[0]), 0, sT, 0, 8);
        System.arraycopy(encryptor.encrypt((h2), key[1]), 0, sT, 8, 8);
        System.arraycopy(encryptor.encrypt((h3), key[2]), 0, sT, 16, 8);
        System.arraycopy(encryptor.encrypt((h4), key[3]), 0, sT, 24, 8);
        
        return sT;
    }

    /**
     * Реализует полное перемешивающее преобразование. Работает на основе {@link #shuffle(byte[])}
     *
     * @param afterCipher данные, полученные на выходе метода {@link #cipher(byte[][], byte[])}
     * @param hIn данные, используемые в роли промежуточной хеш-функции
     * @param m данные, используемые в роли промежуточного сообщения
     * @return массив перемешанных байт
     */
    private static byte[] shuffleFull(byte[] afterCipher, byte[] hIn, byte[] m) {
        for (int i = 0; i < 12; i++) {
            shuffle(afterCipher);
        }
        sumXorArray(afterCipher, m);
        shuffle(afterCipher);
        sumXorArray(afterCipher, hIn);
        for (int i = 0; i < 61; i++) {
            shuffle(afterCipher);
        }
        
        return afterCipher;
    }

    /**
     * Реализует один шаг перемешивающего преобразования
     *
     * @param afterCipher данные для перемешивания
     * @return массив перемешанных байт
     */
    private static void shuffle(byte[] afterCipher) {
        byte shuffleTemp30 = (byte) (afterCipher[0] ^ afterCipher[2] ^ afterCipher[4] ^ afterCipher[6] ^ afterCipher[24]
                ^ afterCipher[30]);
        byte shuffleTemp31 = (byte) (afterCipher[31] ^ afterCipher[25] ^ afterCipher[7] ^ afterCipher[5]
                ^ afterCipher[3] ^ afterCipher[1]);
                
        for (int i = 0; i < 30; i++) {
            byte shuffleTemp = afterCipher[i + 2];
            afterCipher[i] = afterCipher[i + 2];
            afterCipher[i] = shuffleTemp;
        }
        afterCipher[31] = shuffleTemp31;
        afterCipher[30] = shuffleTemp30;
    }

    /**
     * Реализует XOR для двух массивов байт
     *
     * @param arg1 входные данные для оперирования
     * @param arg2 входные данные для оперирования
     */
    private static void sumXorArray(byte[] arg1, byte[] arg2) {
        for (int i = 0; i < arg1.length; i++) {
            arg1[i] = (byte) (arg1[i] ^ arg2[i]);
        }
    }
}
