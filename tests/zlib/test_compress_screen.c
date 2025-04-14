#include "myzip.h"
#include "file_util.h"
#include "win_misc.h"
#include <string.h>

#define IMAGE_NAME L"test_image.bmp"

void write_image(char * data, size_t size)
{
    wchar_t * e_dir = exe_dir();
    wchar_t * path = concat_filename(e_dir, IMAGE_NAME);

    void * file = CreateFileWin32(path);
    WriteFileWin32(data, size, file);
    CloseFileWin32(file);
}

boolean test_take_screen_and_compare()
{
    int32_t err, zlib_error, cmpRes;
    boolean isSizesEq, isBytesEq, testPassed;
    size_t imageFullSize, imageFullSizeBufSize;
    uint32_t imageCompressedSize;
    char * image, * compressedImage;
    

    image = CaptureScreen(&imageFullSize);    

    if (!image) return -1;

    // deflating (compressing)
    compressedImage = encode_deflate(image, (uint32_t)imageFullSize, &imageCompressedSize, Z_MAX);

    imageFullSizeBufSize = imageFullSize;

    // inflating (decompressing)
    char * imgRestoreBuffer = malloc(imageFullSize);
    zlib_error = uncompress((Bytef*)imgRestoreBuffer, 
                            (uLongf*)&imageFullSizeBufSize, 
                            (const Bytef*)compressedImage, 
                            imageCompressedSize);

    if (zlib_error != Z_OK) return -1;

    // checking image sizes

    
    isSizesEq = (imageFullSizeBufSize == imageFullSize);

    // checking images bytes

    isBytesEq = (!memcmp(image, imgRestoreBuffer, imageFullSize)) ? true : false;    

    testPassed = (isSizesEq && isBytesEq);

    if (testPassed) {

        write_image(imgRestoreBuffer, imageFullSizeBufSize);

    }

    return testPassed;
}



int main(int argc, char ** argv)
{
    int err;
    err = test_take_screen_and_compare() ? 0 : 1;
    return err;
}