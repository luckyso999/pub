package pub

import (
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	crypto_rand "crypto/rand"
	"image"
	"math"
	"mime/multipart"
	"runtime"
	"sync"

	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/base64"
	"encoding/binary"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image/gif"
	"image/jpeg"
	"image/png"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	"golang.org/x/image/draw"
	"gopkg.in/ini.v1"

	"github.com/google/uuid"
	"github.com/parnurzeal/gorequest"
	"github.com/skip2/go-qrcode"
	"github.com/tidwall/gjson"
)

var (
	UseProxy       = true
	proxyUrl       = "http://127.0.0.1:8888"
	muWriteLog     sync.Mutex
	CookieBilibili string
)

type FetchRequest struct {
	URL     string            `json:"url"`
	Method  string            `json:"method"`
	Headers map[string]string `json:"headers"`
	Body    []byte            `json:"body"`
}

func FetchToJSON(fetchCall string) (FetchRequest, error) {

	url := GetBetweenStr(fetchCall, "fetch(\"", "\"")
	// 移除最外层的双引号
	jsonString := "{" + fmt.Sprintf(`"url": "%s",`, url)

	body := jsonString + GetBetweenStr(fetchCall, "{", "});") + "}"
	fmt.Printf("body: %v\n", body)
	var fetchReq FetchRequest
	if err := json.Unmarshal([]byte(body), &fetchReq); err != nil {
		log.Printf("JSON Unmarshal error: %v", err)
	}

	return fetchReq, nil
}

func ParseRawRequest(rawRequest string) FetchRequest {
	var fetchReq FetchRequest
	lines := strings.Split(rawRequest, "\n")
	requestLine := strings.Fields(lines[0])
	fetchReq.Method = requestLine[0]
	fetchReq.URL = requestLine[1]
	fetchReq.Headers = make(map[string]string)
	// headers := make(http.Header)
	var body string

	// Read header lines until we get to the body
	for _, line := range lines[1:] {
		if line == "" {
			break // End of headers
		}
		if strings.Contains(line, "Accept-Encoding") {
			// 去掉Accept-Encoding头部，防止被压缩
			continue
		}
		if strings.Contains(line, "Content-Length") {
			// 去掉Content-Length头部，防止被修改
			continue
		}
		parts := strings.SplitN(line, ": ", 2)
		fetchReq.Headers[parts[0]] = parts[1]
	}
	// The rest is the body (if any)
	bodyIndex := strings.Index(rawRequest, "\n\n")
	if bodyIndex != -1 {
		body = rawRequest[bodyIndex+len("\n\n"):]
	}
	fetchReq.Body = []byte(body)
	return fetchReq
}

func FetchHTTPRequest(fetchReq FetchRequest) string {
	client := &http.Client{}

	// 如果提供了代理URL，则设置代理
	if proxyUrl != "" {
		proxy, err := url.Parse(proxyUrl)
		if err != nil {
			log.Fatalf("Error parsing proxy URL: %v", err)
		}
		client.Transport = &http.Transport{
			Proxy: http.ProxyURL(proxy),
		}
	}

	// 构建新的请求
	req, err := http.NewRequest(fetchReq.Method, fetchReq.URL, bytes.NewReader(fetchReq.Body))
	if err != nil {
		log.Printf("Error creating request: %v", err)
	}

	// 设置请求头
	for key, value := range fetchReq.Headers {
		req.Header.Set(key, value)
	}

	// 发送请求
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error sending request: %v", err)
	}
	defer resp.Body.Close()

	// 读取并输出响应
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error reading response body: %v", err)
	}

	log.Printf("Response Status: %s", resp.Status)
	log.Printf("Response Body: \n%s", string(responseBody))
	return string(responseBody)
}

func Go(x func()) {
	go func() {
		defer func() {
			if err := recover(); err != nil {
				fmt.Printf("err: %v\n", err)
				fmt.Println(string(debug.Stack()))
			}
		}()
		x()
	}()
}

func PostcData(PostUrl string, cData []byte, Header map[string][]string) string {
	var client http.Client
	if UseProxy {
		proxyUrl := "http://127.0.0.1:8888"
		urlproxy, _ := url.Parse(proxyUrl)
		client = http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				Proxy: http.ProxyURL(urlproxy),
			},
		}
	} else {
		client = http.Client{
			Timeout: 30 * time.Second,
		}
	}
	req, err := http.NewRequest("POST", PostUrl, bytes.NewReader(cData))
	if err != nil {
		fmt.Println("Error creating HTTP request:", err)
		return ""
	}
	req.Header = Header

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending HTTP request:", err)
		return ""
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response body:", err)
		return ""
	}

	ret := string(body)
	fmt.Printf("ret: %v\n", ret)
	return ret
}

// 读取key=value类型的配置文件
func InitConfig(path string) map[string]string {
	config := make(map[string]string)

	f, err := os.Open(path)
	if err != nil {
		panic(err)
	}

	r := bufio.NewReader(f)
	for {
		b, _, err := r.ReadLine()
		if err != nil {
			if err == io.EOF {
				break
			}
			panic(err)
		}
		s := strings.TrimSpace(string(b))
		index := strings.Index(s, "=")
		if index < 0 {
			continue
		}
		key := strings.TrimSpace(s[:index])
		if len(key) == 0 {
			continue
		}
		value := strings.TrimSpace(s[index+1:])
		if len(value) == 0 {
			continue
		}
		config[key] = value
	}
	f.Close()
	return config
}

func IsDebugMode() bool {
	// 获取当前可执行文件的路径
	exePath, err := os.Executable()
	if err != nil {
		fmt.Println("无法获取可执行文件路径:", err)
		return false
	}

	// 判断可执行文件路径中是否包含 "debug"
	return strings.Contains(strings.ToLower(exePath), "debug")
}

// panic("something went wrong")
// 检测错误后打印
func CheckError(e error) {
	if e != nil {
		fmt.Println(e)
	}
}

func NewUUID() string {
	uuid, err := uuid.NewUUID()
	if err != nil {
		fmt.Printf("err: %v\n", err)
		return ""
	}
	return uuid.String()
}

func StrToBase64(Str string) string {
	return base64.StdEncoding.EncodeToString([]byte(Str))
}

func Base64ToStr(Base64 string) string {
	bytes, err := base64.StdEncoding.DecodeString(Base64)
	if err != nil {
		return ""
	}
	return string(bytes)
}

func ReadIni(iniFileName, Section, key string) *ini.Key {
	cfg, err := ini.Load(iniFileName)
	if err != nil {
		fmt.Printf("Fail to read file: %v", err)
	}
	// 典型读取操作，默认分区可以使用空字符串表示
	return cfg.Section(Section).Key(key)
	// conf := InitConfig(iniFileName)
	// return conf.GetValue("root", key)
}

func WriteIni(iniFileName, Section, key, value string) {
	cfg, err := ini.Load(iniFileName)
	if err != nil {
		fmt.Printf("Fail to read file: %v", err)
	}
	cfg.Section(Section).Key(key).SetValue(value)
	cfg.SaveTo(iniFileName)
}

func FileSplitCount(fileSize int64, splitSize int64) int {
	return int((fileSize + splitSize - 1) / splitSize)
}

func get10MFileMD5(filePath string, size int64) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()
	// 创建一个用于计算哈希值的 hash.Hash 对象
	hash := md5.New()
	// 使用 io.CopyN 将前 10MB 的数据复制到 hash 中
	if _, err := io.CopyN(hash, file, 10*1024*1024); err != nil {
		return "", err
	}
	// 读取文件的后 10MB
	if _, err := file.Seek(-10*1024*1024, 2); err != nil {
		return "", err
	}
	if _, err := io.CopyN(hash, file, 10*1024*1024); err != nil {
		return "", err
	}
	hash.Write([]byte(filepath.Base(filePath)))
	hash.Write([]byte(fmt.Sprint(size)))

	// 计算哈希值并返回
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

// 获取文件的md5码
func GetFileMd5(filename string) string {
	const DEFAULT int64 = 100 * 1024 * 1024
	if !PathExists(filename) {
		return ""
	}
	finfo, _ := os.Stat(filename)

	if finfo.Size() < DEFAULT {
		pFile, _ := os.Open(filename)
		defer pFile.Close()
		md5h := md5.New()
		buf := make([]byte, 1024000)
		io.CopyBuffer(md5h, pFile, buf)
		return hex.EncodeToString(md5h.Sum(nil))
	} else {
		md5h, _ := get10MFileMD5(filename, finfo.Size())
		return md5h
	}
}

// 获取数据的md5码
func GetByteMd5(data []byte) string {
	// md5 := md5.New()
	// md5.Write(data)
	// md5Str := hex.EncodeToString(md5.Sum(nil))
	// return md5Str
	return fmt.Sprintf("%x", md5.Sum(data))
}

// func SaveConfigToFile() {
// 	data, err := json.Marshal(&config) //通过json包下的Marshal函数对结构体进行转换
// 	if err != nil {
// 		fmt.Println(err)
// 	}
// 	// data= GZipBytes(data)
// 	os.WriteFile(jsonFileName, data, 0777)
// }

// func ReadToConfig() {
// 	data, _ := os.ReadFile(jsonFileName)
// 	// data = UGZipBytes(data)
// 	err := json.Unmarshal([]byte(string(data)), &config) //反序列化，通过[]byte(str)类型断言将str转换为切片
// 	if err != nil {
// 		fmt.Printf("unmarshal err=%v\n", err)
// 	}
// }

func FunProcessTime(函数名字 string, start time.Time) {
	// 使用time.Since获取经过的时间
	elapsedTime := time.Since(start)

	// 如果经过的时间超过了限制，输出警告信息
	// if elapsedTime > timeLimit {
	// elapsedTime = elapsedTime.Truncate(time.Millisecond)

	// strTime := fmt.Sprint(elapsedTime)

	minutes := int(elapsedTime.Minutes()) % 60
	seconds := int(elapsedTime.Seconds()) % 60
	milliseconds := elapsedTime.Milliseconds() % 1000

	// 格式化为字符串
	strTime := fmt.Sprintf("%02d:%02d.%02d", minutes, seconds, milliseconds)

	Println(函数名字, ":", "已用时", strTime)
	// }
}

// 压缩
func GZipBytes(data []byte) []byte {
	var input bytes.Buffer
	g := gzip.NewWriter(&input)
	g.Write(data)
	g.Close()
	return input.Bytes()
}

// 解压
func UGZipBytes(data []byte) []byte {
	var out bytes.Buffer
	var in bytes.Buffer
	in.Write(data)
	r, _ := gzip.NewReader(&in)
	r.Close()
	io.Copy(&out, r)
	return out.Bytes()
}

// 获取文件原来的访问时间，修改时间
func GetFileModTime(pathname string) int64 {
	finfo, _ := os.Stat(pathname)
	// windows下代码如下
	return finfo.ModTime().Unix()
}

func GetFileSize(pathname string) int64 {
	finfo, _ := os.Stat(pathname)
	// windows下代码如下
	return finfo.Size()
}

// func WalkDir(dirPth string) (err error) {
// 	err = filepath.Walk(dirPth, func(FileName string, fi os.FileInfo, err error) error { //遍历目录
// if err != nil { //忽略错误
// 	return err
// }
// if !fi.IsDir() {
// 	if fi.Size() != 0 {
// if Files[FileName] == nil || Files[FileName].UpCheckFile(FileName) {
// 	fileInfo, err := NewUpFileinfo(FileName)
// 	Files[FileName] = fileInfo
// 	if err == nil {
// 		ChanUpFileinfo <- fileInfo
// 	}
// }
// 	}
// }
// 		return nil
// 	})
// 	return err
// }

func MakeFileSize(fileName string, fileSize int64) {
	// os.WriteFile(fileName, make([]byte, fileSize), 0666)
	// out, _ := os.Create(fileName)
	// defer out.Close()
	// io.CopyN(out, io.LimitReader(cryRand.Reader, fileSize), fileSize)
	f, _ := os.Create(fileName)
	defer f.Close()
	f.Truncate(fileSize)
}

func CheckDirDelete(dirPth, savePath string) (err error) {
	err = filepath.Walk(savePath, func(FileName string, fi os.FileInfo, err error) error { //遍历目录
		localFileName := strings.Replace(FileName, savePath, dirPth, 1)

		if !PathExists(localFileName) {
			fmt.Printf("本地文件已删除: %v\n", localFileName)
			if IsFile(FileName) {
				os.Remove(FileName)
			} else {
				os.RemoveAll(FileName)
			}
		}
		return nil
	})
	return err
}

// 判断文件是否存在
func PathExists(path string) bool {
	_, err := os.Stat(path)
	if err == nil {
		return true
	}
	if os.IsNotExist(err) {
		return false
	}
	return false
}

func RandStringRunes(n int) string {
	var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	// fmt.Printf("b: %v\n", string(b))
	return string(b)
}

func ResizeImage(img image.Image, width, height int) image.Image {
	// 如果高度为0，则根据宽度等比例缩放
	if height == 0 {
		height = img.Bounds().Dy() * width / img.Bounds().Dx()
	}

	// 创建目标大小的图像
	dst := image.NewRGBA(image.Rect(0, 0, width, height))

	// 将原始图像缩放到目标大小
	draw.CatmullRom.Scale(dst, dst.Bounds(), img, img.Bounds(), draw.Over, nil)

	return dst
}

func MergeBytes(a, b []byte, index int) []byte {
	if index < 0 {
		// 如果 index 是负数，则默认插入位置为 0。
		index = 0
	}
	if index > len(a) {
		// 如果 index 超出数组 a 的长度，b 附加在 a 之后。
		return append(a, b...)
	}

	// 使用 append 和 copy 函数进行插入。
	return append(a[:index], append(b, a[index:]...)...)
}

func MergeBytesTruncateA(a, b []byte, index int) []byte {
	// 如果 index 超出数组 a 的长度，或 index 是负数，则不包含 a 的任何部分。
	if index >= len(a) || index < 0 {
		return b
	}
	// 合并 a 的前半部分和 b。
	return append(a[:index], b...)
}

func QrcodeFile(text string, size int) []byte {
	// size := 256
	code, _ := qrcode.New(text, qrcode.Highest)
	srcImage := code.Image(size)
	buf := bytes.Buffer{}
	jpeg.Encode(&buf, srcImage, &jpeg.Options{Quality: 90})
	return buf.Bytes()
}

func QrcodeGifFile(text string, size int) []byte {
	// size := 256
	code, _ := qrcode.New(text, qrcode.Highest)
	srcImage := code.Image(size)
	buf := bytes.Buffer{}
	gif.Encode(&buf, srcImage, &gif.Options{})
	return buf.Bytes()
}

func GetUserAgent() string {
	rnd := fmt.Sprint(rand.Intn(10), ".", rand.Intn(100))
	UserAgent := "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/53" + rnd + " (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/53" + rnd
	return UserAgent
}

func RandInt(min, max int) int {
	if min >= max || min == 0 || max == 0 {
		return max
	}
	rand.Seed(time.Now().UnixNano())
	return rand.Intn(max-min) + min
}

func GetBetweenStr(str, starting, ending string) (retStr string) {
	s := strings.Index(str, starting)
	if starting == "" {
		s = 0
	}
	if s < 0 {
		return ""
	}
	s += len(starting)
	e := strings.Index(str[s:], ending)
	if ending == "" {
		return str[s:]
	}
	if e < 0 {
		return ""
	}
	return str[s : s+e]
}

func isEmptyDir(dirname string) bool {
	dir, _ := os.ReadDir(dirname)
	if len(dir) == 0 {
		fmt.Println(dirname + " is empty dir!")
		return true
	} else {
		fmt.Println(dirname + " is not empty dir!")
		return false
	}
}

func zipDir(dir, zipFile string) {

	fz, err := os.Create(zipFile)
	if err != nil {
		log.Fatalf("Create zip file failed: %s\n", err.Error())
	}
	defer fz.Close()

	w := zip.NewWriter(fz)
	defer w.Close()

	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || path == dir {
			return nil
		}
		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		if !info.IsDir() {
			header.Method = zip.Deflate
		}
		header.Modified = info.ModTime()
		// header.SetModTime(time.Unix(info.ModTime().Unix()+(8*60*60), 0))
		header.Name = path[len(dir)+1:]

		// if err != nil {
		// 	return err
		// }
		if !info.IsDir() {
			fDest, err := w.CreateHeader(header)
			if err != nil {
				log.Printf("Create failed: %s\n", err.Error())
				return nil
			}
			fSrc, err := os.Open(path)
			if err != nil {
				log.Printf("Open failed: %s\n", err.Error())
				return nil
			}
			defer fSrc.Close()
			_, err = io.Copy(fDest, fSrc)
			if err != nil {
				log.Printf("Copy failed: %s\n", err.Error())
				return nil
			}
		} else {
			if isEmptyDir(path) {
				// fmt.Println(fmt.Sprintf("%s%c", path, os.PathSeparator))
				_, err := w.Create(path[len(dir)+1:] + "\\空目录")
				if err != nil {
					fmt.Printf("err: %v\n", err)
				}
			}

		}
		return nil
	})
}

func unzipDir(zipFile, dir string) {

	r, err := zip.OpenReader(zipFile)
	if err != nil {
		log.Fatalf("Open zip file failed: %s\n", err.Error())
	}
	defer r.Close()

	for _, f := range r.File {
		func() {
			path := dir + string(filepath.Separator) + f.Name
			os.MkdirAll(filepath.Dir(path), 0755)
			fDest, err := os.Create(path)
			if err != nil {
				log.Printf("Create failed: %s\n", err.Error())
				return
			}
			defer fDest.Close()

			fSrc, err := f.Open()
			if err != nil {
				log.Printf("Open failed: %s\n", err.Error())
				return
			}
			defer fSrc.Close()

			_, err = io.Copy(fDest, fSrc)
			if err != nil {
				log.Printf("Copy failed: %s\n", err.Error())
				return
			}
		}()
	}
}

// 以1000作为基数
func ByteCountSI(b int64) string {
	const unit = 1000
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB",
		float64(b)/float64(div), "kMGTPE"[exp])
}

// 以1024作为基数
func ByteCountIEC(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB",
		float64(b)/float64(div), "KMGTPE"[exp])
}

func downloadRate(dataSize int64, startTime int64) int64 {
	endTime := time.Now().Unix()
	elapsedTime := endTime - startTime + 1
	rate := dataSize / elapsedTime
	return rate
}

func IsFile(f string) bool {
	fi, e := os.Stat(f)
	if e != nil {
		return false
	}
	return !fi.IsDir()
}

func GetPercent(DoneCount, FileCount int) int {
	return int((float64(DoneCount) / float64(FileCount)) * 100)
}

func PostData(PostUrl string, Header http.Header, Data []byte) (ret string, err error) {
	c1 := http.Client{
		Timeout: 30 * time.Second,
	}
	//设置为不用代理,防止抓包  还有可以检测是否在代理环境
	// proxyUrl := "http://127.0.0.1:8888"
	// urlproxy, _ := url.Parse(proxyUrl)
	// c1 := http.Client{
	// 	Timeout: 30 * time.Second,
	// 	Transport: &http.Transport{
	// 		Proxy: http.ProxyURL(urlproxy),
	// 	},
	// }
	req, _ := http.NewRequest("POST", PostUrl, bytes.NewReader(Data))
	req.Header = Header
	resp, err := c1.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	ret = string(body)
	return
}

func PKCS7UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func AesEncrypt(origData, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()
	// fmt.Println(blockSize)
	origData = PKCS5Padding(origData, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, key[:blockSize])
	// fmt.Println(len(origData))
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)
	return crypted, nil
}

func AesDecrypt(crypted, key []byte, ivs ...[]byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	var iv []byte
	if len(ivs) == 0 {
		iv = key
	} else {
		iv = ivs[0]
	}
	blockMode := cipher.NewCBCDecrypter(block, iv[:blockSize])
	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)
	origData = PKCS7UnPadding(origData)
	return origData, nil
}

// 生成boundary值
func GenerateBoundary() string {
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	randBytes := make([]byte, 16) // 16个字符长度
	if _, err := rand.Read(randBytes); err != nil {
		panic(err)
	}
	for i := range randBytes {
		randBytes[i] = letters[randBytes[i]%byte(len(letters))]
	}
	return string(randBytes)
}

func ProcessPostData(Data []byte) []byte {
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("ProcessPostData错误:", r)
		}
	}()

	// cData := []byte{}

	aFile := QrcodeFile("http://goo.gl/"+RandStringRunes(RandInt(10, 20))+fmt.Sprint(time.Now().UnixMicro()), 256)
	// aFile = aFile[:len(aFile)/2]
	aFile[len(aFile)-1] = byte(rand.Intn(200))
	aFile[len(aFile)-2] = byte(rand.Intn(200))

	token := make([]byte, 0)
	if len(aFile) < 32000 {
		token = make([]byte, 32000-len(aFile))
		crypto_rand.Read(token)
	}
	// panic("something went wrong")

	// aData := []byte("------WebKitFormBoundary" + Boundary + "\r\nContent-Disposition: form-data; name=\"file\"; filename=\"" + Boundary + ".jpg" + "\"\r\nContent-Type: image/jpeg\r\n\r\n")
	// dData := []byte("\r\n------WebKitFormBoundary" + Boundary + "--\r\n")

	// reverseBytes(Data)

	cData := AppendData(token, aFile, Data)

	return cData
}

func ReverseBytes(data []byte) {
	for i := len(data)/2 - 1; i >= 0; i-- {
		opp := len(data) - 1 - i
		data[i], data[opp] = data[opp], data[i]
	}
}

// RandomFileFromZip 从ZIP文件中随机选取一个文件并返回其内容
func RandomFileFromZip(zipPath string) ([]byte, error) {
	// 打开ZIP文件
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return nil, fmt.Errorf("无法打开ZIP文件：%w", err)
	}
	defer zr.Close()

	// 确保ZIP不为空
	if len(zr.File) == 0 {
		return nil, fmt.Errorf("ZIP文件中不包含文件")
	}

	// 随机选择一个文件
	randomIndex := GetRandomInt(0, len(zr.File)-1)
	selectedFile := zr.File[randomIndex]
	// 打开选中的文件
	f, err := selectedFile.Open()
	if err != nil {
		return nil, fmt.Errorf("无法打开文件：%w", err)
	}
	defer f.Close()

	// 使用io.Copy将文件内容复制到缓冲区
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, f); err != nil {
		return nil, fmt.Errorf("无法复制文件内容：%w", err)
	}

	return buf.Bytes(), nil
}

func GetRandomInt(min, max int) int {
	source := rand.NewSource(time.Now().UnixNano())
	r := rand.New(source)
	return r.Intn(max-min+1) + min
}

func AppendData(data []byte, prefixData []byte, suffixData []byte) []byte {
	// 将前缀数据和后缀数据与原始数据合并
	cData := append(append(prefixData, data...), suffixData...)
	return cData
}

func DownloadPartData(fileUrl string, Header map[string][]string) ([]byte, error) {
	var client http.Client
	if UseProxy {
		proxyUrl := "http://127.0.0.1:8888"
		urlproxy, _ := url.Parse(proxyUrl)
		client = http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				Proxy: http.ProxyURL(urlproxy),
			},
		}
	} else {
		client = http.Client{
			Timeout: 30 * time.Second,
		}
	}

	// 发送HTTP GET请求
	req, _ := http.NewRequest("GET", fileUrl, nil)
	// 设置Header
	req.Header = Header
	req.Header.Set("Content-Type", "image/jpeg")
	req.Header.Set("Referer", "https://docs.qq.com/doc/DWVVLYUFFZExHeWhV")
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-", 32000))

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending HTTP request:", err)
		return nil, err
	}
	defer resp.Body.Close()

	// 读取响应体
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response body:", err)
		return nil, err
	}

	return body, nil
}

func Println(v ...interface{}) {
	// 将参数格式化为字符串
	format := strings.TrimRight(strings.Repeat("%v, ", len(v)), ", ")
	// 格式化消息
	message := fmt.Sprintf(format, v...)
	// 写入日志
	fmt.Println(message)
	WriteLog(message, "app.log", true)
}

func WriteLog(info string, fileName string, addTime bool) bool {
	muWriteLog.Lock()
	defer muWriteLog.Unlock()
	// 如果文件名没有路径分隔符，则在当前目录下的"logs"目录建立一个当前日期的子目录
	if !strings.Contains(fileName, string(filepath.Separator)) {
		currentDate := time.Now().Format("2006-01-02")
		fileName = filepath.Join("logs", currentDate, fileName)
	}
	os.MkdirAll(filepath.Dir(fileName), 0777)
	file, err := os.OpenFile(fileName, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		fmt.Println("文件打开失败", err)
	}
	//及时关闭file句柄
	defer file.Close()
	if addTime {
		file.WriteString(time.Now().Format("2006-01-02 15:04:05 ") + info + "\r\n")
	} else {
		file.WriteString(info + "\r\n")
	}
	return false
}

// 将数据保存到 Gob 文件
func SaveToGob(filename string, data []map[string]string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := gob.NewEncoder(file)
	if err := encoder.Encode(data); err != nil {
		return err
	}
	fmt.Printf("Data saved to %s\n", filename)
	return nil
}

// 从 Gob 文件中加载数据
func LoadFromGob(filename string) ([]map[string]string, error) {
	var loadedData []map[string]string

	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	decoder := gob.NewDecoder(file)
	if err := decoder.Decode(&loadedData); err != nil {
		return nil, err
	}
	fmt.Printf("Data loaded from %s\n", filename)
	return loadedData, nil
}

func intToBytes(n int) []byte {
	bytes := make([]byte, 8)                     // 创建一个长度为8的字节切片
	binary.BigEndian.PutUint64(bytes, uint64(n)) // 将整数n转换为字节，并存储在字节切片中
	return bytes
}

func bytesToInt(bytes []byte) int {
	return int(binary.BigEndian.Uint64(bytes)) // 将字节切片转换回整数
}

func DataToImage(data []byte) []byte {
	size := len(data) + 8
	width := int(math.Ceil(math.Sqrt(float64(size+1) / 4)))
	img := image.NewNRGBA(image.Rect(0, 0, width, width))
	copy(img.Pix, intToBytes(len(data)))
	copy(img.Pix[8:], data)

	buf := new(bytes.Buffer)
	err := png.Encode(buf, img)
	if err != nil {
		fmt.Println("出现错误:", err)
		return nil
	}

	return buf.Bytes()
}

func ImageToData(imageData []byte) []byte {
	imgReader := bytes.NewReader(imageData)
	img, err := png.Decode(imgReader)
	if err != nil {
		fmt.Println("出现错误:", err)
		return nil
	}

	nrgba, ok := img.(*image.NRGBA)
	if !ok {
		fmt.Println("出现错误:不能转换图像为NRGBA")
		return nil
	}

	dataSize := bytesToInt(nrgba.Pix[:8])
	data := nrgba.Pix[8 : dataSize+8]

	return data
}

func FileToImage(filename string, imgName string) {
	data, err := os.ReadFile(filename)
	if err != nil {
		fmt.Println("出现错误:", err)
	}

	imageData := DataToImage(data)

	err = os.WriteFile(imgName, imageData, 0644)
	if err != nil {
		fmt.Println("出现错误:", err)
	}
}

func ImageToFile(imgName string, filename string) {
	imageData, err := os.ReadFile(imgName)
	if err != nil {
		fmt.Println("出现错误:", err)
	}

	data := ImageToData(imageData)

	err = os.WriteFile(filename, data, 0644)
	if err != nil {
		fmt.Println("出现错误:", err)
	}
}

func DownloadFileFromB(url string) ([]byte, error) {
	rangeHeader := "bytes=60000-"
	_, body, errs := gorequest.New().Get(url).
		Set("Range", rangeHeader).
		EndBytes()

	if len(errs) > 0 {
		return nil, fmt.Errorf("错误下载数据: %v", errs[0])
	}
	rData, _ := AesDecrypt(body, []byte("ca2788cb8eb9e8c9"))
	return rData, nil
}

// 下载并合并分段数据到文件
func DownloadBFile(finalURL, outputFilePath string) error {
	const separator = "{\"partURLs\":["
	// 打开输出文件
	outputFile, err := os.Create(outputFilePath)
	if err != nil {
		return fmt.Errorf("错误打开输出文件: %v", err)
	}
	defer outputFile.Close()

	// 下载初始文件数据
	initialData, err := DownloadFileFromB(finalURL)
	if err != nil {
		return fmt.Errorf("错误下载初始文件数据: %v", err)
	}

	// 检查数据是否包含分隔符
	if bytes.HasPrefix(initialData, []byte(separator)) {
		// 提取 JSON 数据部分
		partURLs := gjson.GetBytes(initialData, "partURLs").Array()

		for _, url := range partURLs {
			partData, err := DownloadFileFromB(url.String())
			if err != nil {
				return fmt.Errorf("下载分段数据失败 %s: %v", url.String(), err)
			}
			_, err = outputFile.Write(partData)
			if err != nil {
				return fmt.Errorf("写入分段数据失败: %v", err)
			}
		}

	} else {
		// 如果没有分隔符，直接写入数据
		_, err = outputFile.Write(initialData)
		if err != nil {
			return fmt.Errorf("写入文件数据失败: %v", err)
		}
	}

	return nil
}

func DownloadFileFromBx(url string) ([]byte, error) {
	rangeHeader := "bytes=60000-"
	const separator = "{\"partURLs\":["

	resp, body, errs := gorequest.New().Get(url).
		Set("Range", rangeHeader).
		EndBytes()

	if len(errs) > 0 {
		return nil, fmt.Errorf("error making request: %v", errs[0])
	}

	fmt.Println(resp.Header)
	rData, _ := AesDecrypt(body, []byte("ca2788cb8eb9e8c9"))
	if bytes.HasPrefix(rData, []byte(separator)) {
		var urlList []string
		parts := bytes.SplitN(rData, []byte(separator), 2)
		json.Unmarshal(parts[0], &urlList)
		AllData := make([]byte, 0)
		for _, url := range urlList {
			Data, _ := DownloadFileFromB(url)
			AllData = append(AllData, Data...)
		}
		rData = append(AllData, parts[1]...)
	}
	return rData, nil
}

func CustomBoundary() string {
	rand.Seed(time.Now().UnixNano())
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	var result []byte
	for i := 0; i < 16; i++ {
		result = append(result, chars[rand.Intn(len(chars))])
	}
	return "----WebKitFormBoundary" + string(result)
}

func UploadFileToB(filePath string, partSize int) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	var partURLs []string
	buffer := make([]byte, partSize)
	for {
		n, _ := file.Read(buffer)
		if n == 0 {
			break
		}
		retStr := UploadDataToB(buffer[:n])
		partUrl := GetBetweenStr(retStr, `location":"`, `"`)
		fmt.Println(partUrl)

		if partUrl == "" {
			return "", fmt.Errorf("错误上传数据,返回值为空")
		}
		partURLs = append(partURLs, partUrl)
	}
	if len(partURLs) > 1 {
		summary := map[string]interface{}{
			"partURLs": partURLs,
		}
		summaryData, _ := json.Marshal(summary)
		retStr := UploadDataToB(summaryData)
		partUrl := GetBetweenStr(retStr, `location":"`, `"`)
		fmt.Println(partUrl)
		return partUrl, nil
	}
	if len(partURLs) > 0 {
		return partURLs[0], nil
	}

	return "", fmt.Errorf("错误上传文件,没有分段数据")
}

// 上传数据到bilibili
func UploadDataToB(tsData []byte) string {
	urlStr := "https://cool.bilibili.com/x/material/up/upload"
	csrf := GetBetweenStr(CookieBilibili, "bili_jct=", ";")
	// aFile := pub.QrcodeFile("http://goo.gl/"+pub.RandStringRunes(pub.RandInt(10, 20))+fmt.Sprint(time.Now().UnixMicro()), 9000)
	// aFile = aFile[:600000]
	content, _ := RandomFileFromZip(`\gif.zip`)
	fileData := content[:len(content)-4]
	token := make([]byte, 60000-len(fileData))
	crypto_rand.Read(token)
	fileData = append(fileData, token...)

	// tsData, _ := os.ReadFile(filePath)
	tsData, _ = AesEncrypt(tsData, []byte("ca2788cb8eb9e8c9"))
	fileData = append(fileData, tsData...)

	// fileData, _ := os.ReadFile(`I:\Code\Go\Code\example\binToPng\1.gif`)
	// fileData = append(aFile, fileData...)

	// Create a buffer to store the request body
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	bounary := CustomBoundary()
	writer.SetBoundary(bounary)

	// Add the other fields
	_ = writer.WriteField("bucket", "material_up")
	_ = writer.WriteField("dir", "")

	// 创建特定的MIME headers
	header := make(textproto.MIMEHeader)
	header.Set("Content-Disposition",
		`form-data; name="file"; filename="blob"`)
	header.Set("Content-Type", "image/png")

	part, err := writer.CreatePart(header)
	if err != nil {
		log.Fatal(err)
	}

	_, _ = io.Copy(part, bytes.NewReader(fileData))

	_ = writer.WriteField("csrf", csrf) // Use your CSRF token here

	// Close the writer
	_ = writer.Close()
	var client http.Client
	if UseProxy {
		proxyUrl := "http://127.0.0.1:8888"
		urlproxy, _ := url.Parse(proxyUrl)
		client = http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				Proxy: http.ProxyURL(urlproxy),
			},
		}
	} else {
		client = http.Client{
			Timeout: 30 * time.Second,
		}
	}
	req, err := http.NewRequest("POST", urlStr, body)
	if err != nil {
		fmt.Println(err)
		return ""
	}

	// Set the content type
	headers := map[string][]string{
		"Content-Type": {"multipart/form-data; boundary=" + bounary},
		// "Accept-Encoding":    {"gzip, deflate, br"},
		"Accept-Language":    {"zh-CN,zh;q=0.9"},
		"Connection":         {"keep-alive"},
		"Host":               {"cool.bilibili.com"},
		"Origin":             {"https://cool.bilibili.com"},
		"Referer":            {"https://cool.bilibili.com/upload-music"},
		"Sec-Fetch-Dest":     {"empty"},
		"Sec-Fetch-Mode":     {"cors"},
		"Sec-Fetch-Site":     {"same-origin"},
		"sec-ch-ua":          {"\"Chromium\";v=\"119\", \"Not?A_Brand\";v=\"24\""},
		"sec-ch-ua-mobile":   {"?0"},
		"sec-ch-ua-platform": {"\"Windows\""},
		"User-Agent":         {GetUserAgent()},
		"Cookie":             {CookieBilibili},
	}

	req.Header = headers
	// Do the request
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return ""
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	fmt.Println("body:", string(respBody))
	fmt.Println("Response Status:", resp.Status)
	return string(respBody)
}

func GetCurrentFunctionName() string {
	// Caller 的参数为 0 表示当前函数，1 表示调用当前函数的函数，依此类推
	pc, _, _, _ := runtime.Caller(1)
	funcObj := runtime.FuncForPC(pc)
	return funcObj.Name()
}

// 函数用时 用于检查执行时间是否超过限制，并输出警告信息。
// 参数：
//   - tag: 标签用于标识警告的来源
//   - detailed: 详细信息，描述执行的具体内容
//   - start: 开始时间，表示代码开始执行的时间点
//   - timeLimit: 时间限制，表示允许的最长执行时间
func FunTime(start time.Time, timeLimit time.Duration) {
	// 使用time.Since获取经过的时间
	elapsedTime := time.Since(start)

	// 如果经过的时间超过了限制，输出警告信息
	if elapsedTime > timeLimit {
		// elapsedTime = elapsedTime.Truncate(time.Millisecond)

		// strTime := fmt.Sprint(elapsedTime)

		minutes := int(elapsedTime.Minutes()) % 60
		seconds := int(elapsedTime.Seconds()) % 60
		milliseconds := elapsedTime.Milliseconds() % 1000

		// 格式化为字符串
		strTime := fmt.Sprintf("%02d:%02d.%02d", minutes, seconds, milliseconds)

		log.Println(GetCurrentFunctionName(), ":", "已用时", strTime)
	}
}

func GorequestGet(Url string) []byte {
	// proxyUrl := ""
	// if UseProxy {
	// 	proxyUrl = "http://127.0.0.1:8888"
	// }

	_, data, err := gorequest.New().
		Get(Url).
		Set("Connection", "Keep-Alive").
		// Set("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundaryftKfGeUavFx3m0Ks").
		Set("Accept", "*/*").
		Set("Accept-Language", "zh-CN,zh;q=0.9").
		Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36").
		Set("Sec-Fetch-Site", "same-origin").
		Set("Sec-Fetch-Mode", "cors").
		Set("Sec-Fetch-Dest", "empty").
		Timeout(time.Second * 20).
		Proxy(proxyUrl).
		// Retry(3, 5*time.Second, http.StatusBadRequest, http.StatusInternalServerError).
		EndBytes()
	if err != nil {
		fmt.Println("err", err)
	}
	// fmt.Println("data:", string(data))
	return data
}
