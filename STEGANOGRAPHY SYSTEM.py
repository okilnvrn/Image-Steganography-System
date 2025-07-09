import customtkinter as ctk
from tkinter import filedialog, messagebox
from PIL import Image
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import time  # Import the time module

# RLE Compression function
def rle_compress(input_string):# Function to perform Run-Length Encoding (RLE) compression on a string
    if not input_string: # Return an empty string if the input is empty
        return ""
    compressed = [] # Initialize an empty list to store compressed parts
    count = 1 # Initialize a counter and the first character for comparison
    previous_char = input_string[0]
    for char in input_string[1:]: # Iterate over the input string starting from the second character
        if char == previous_char:
            count += 1 # If the current character matches the previous one, increment the count
        else:
            compressed.append(f"({count}){previous_char}")  # Otherwise, append the count and character in the format "(count)char"
            count = 1  # Reset the count and update the previous character
            previous_char = char
    compressed.append(f"({count}){previous_char}") # Append the last character and its count to the compressed list
    return ''.join(compressed)   # Join the list into a single compressed string and return it

# RLE Decompression function
def rle_decompress(compressed_string):
    if not compressed_string:# Return an empty string if the compressed input is empty
        return ""
    decompressed = [] # Initialize an empty list to store decompressed characters
    count = ''  # Temporary variable to store the count as a string
    reading_count = False # Boolean flag to track if we're reading a count inside parentheses
    for char in compressed_string: # Iterate over each character in the compressed string
        if char == '(':
            reading_count = True # When encountering '(', start reading the count
            count = '' # Reset the count
        elif char == ')':
            reading_count = False  # When encountering ')', stop reading the count
        elif reading_count:
            count += char  # If inside parentheses, build the count as a string
        else:
            if count: # If not inside parentheses:
                decompressed.append(char * int(count)) # If there's a count stored, multiply the character by the count and append
                count = '' # Reset the count after using it
            else:
                decompressed.append(char) # If no count, simply append the character
    return ''.join(decompressed) # Join the decompressed list into a single string and return it

# AES Encryption function
def encrypt_text(key, plain_text): # Function to encrypt plaintext using AES in CFB mode
    iv = os.urandom(16)  # Generate a random Initialization Vector (IV) of 16 bytes
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend()) # Create an AES cipher object with the provided key and IV in CFB (Cipher Feedback) mode
    encryptor = cipher.encryptor()  # Create an encryptor object from the cipher to handle encryption
    cipher_text = encryptor.update(plain_text) + encryptor.finalize() # Encrypt the plaintext using the encryptor, finalizing the encryption process
    return iv + cipher_text  # Combine the IV and ciphertext; the IV is needed for decryption later

# AES Decryption function
def decrypt_text(key, combined): # Function to decrypt ciphertext using AES in CFB mode
    iv = combined[:16] # Extract the IV (first 16 bytes) from the combined input
    cipher_text = combined[16:] # Extract the actual ciphertext (bytes after the IV)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend()) # Create an AES cipher object with the same key and IV in CFB mode
    decryptor = cipher.decryptor()  # Create a decryptor object from the cipher to handle decryption
    return decryptor.update(cipher_text) + decryptor.finalize()  # Decrypt the ciphertext using the decryptor, finalizing the decryption process

# Steganography Encoding function
def encode_message(image_path, message, output_path): 
    img = Image.open(image_path)  # Open the input image
    binary_message = ''.join(format(ord(i), '08b') for i in message) + '00000000' # Convert the message to a binary string and add a termination marker ('00000000')
    data_index = 0 # Initialize a data index to keep track of the binary message bit to embed
    pixels = img.load() # Load the image pixels into a modifiable format
    for i in range(img.size[0]):  # Loop through image width
        for j in range(img.size[1]): # Loop through image height
            pixel = list(pixels[i, j])  # Get the pixel values (RGB as a list)
            # Modify the least significant bit (LSB) of each color channel (R, G, B)
            for k in range(3): # Loop through RGB channels
                if data_index < len(binary_message): # Ensure there's still data to embed
                    pixel[k] = (pixel[k] & ~1) | int(binary_message[data_index])  # Set the LSB to the current bit of the binary message
                    data_index += 1  # Move to the next bit in the binary message
            pixels[i, j] = tuple(pixel)  # Update the pixel with the modified RGB values
            if data_index >= len(binary_message):   # If all message bits are embedded, save the image and exit
                img.save(output_path) # Save the modified image to the output path
                return

# Steganography Decoding function
def decode_message(image_path):
    img = Image.open(image_path) # Open the image containing the embedded message
    binary_message = ''  # Initialize a binary string to store the extracted bits
    pixels = img.load() # Load the image pixels

     # Iterate over each pixel in the image
    for i in range(img.size[0]): # Loop through image width
        for j in range(img.size[1]): # Loop through image height
            pixel = pixels[i, j]  # Get the pixel values (RGB tuple)
            
            # Extract the LSB of each color channel (R, G, B)
            for k in range(3): # Loop through RGB channels
                binary_message += str(pixel[k] & 1)  # Append the LSB to the binary message
                if len(binary_message) >= 8 and binary_message[-8:] == '00000000':   # Check for termination marker ('00000000') indicating the end of the message
                    # Convert the binary string to a text message (excluding the termination marker)
                    return ''.join([chr(int(binary_message[i:i+8], 2)) for i in range(0, len(binary_message) - 8, 8)])

    # If no termination marker is found, return the decoded message (without a marker)
    return ''.join([chr(int(binary_message[i:i+8], 2)) for i in range(0, len(binary_message), 8)])

# Image to Binary function
def image_to_binary(image_path):# Converts an image into a binary string representation
    with Image.open(image_path) as img:  # Open the image file and ensure it is in RGB format
        img = img.convert("RGB")  # Ensures the image is in RGB mode (3 channels: Red, Green, Blue)
        width, height = img.size  # Get the dimensions of the image (width and height in pixels)
        binary_data = ''.join(f'{r:08b}{g:08b}{b:08b}' for r, g, b in img.getdata())  # Convert each pixel's RGB values to binary strings and concatenate them
        return binary_data, width, height  # Return the binary representation of the image along with its dimensions

# Binary to Image function
def binary_to_image(binary_data, image_path, width, height): # Converts a binary string representation back into an image
    # Reconstruct the RGB pixel data from the binary string
    pixels = [(
        int(binary_data[i:i+8], 2), # Extract and convert the Red channel (8 bits)
        int(binary_data[i+8:i+16], 2), # Extract and convert the Green channel (8 bits)
        int(binary_data[i+16:i+24], 2) # Extract and convert the Blue channel (8 bits)
    ) for i in range(0, len(binary_data), 24)] # Process 24 bits (3 channels x 8 bits) at a time
    
    img = Image.new("RGB", (width, height)) # Create a new RGB image with the specified dimensions
    img.putdata(pixels)  # Assign the reconstructed pixel data to the image
    img.save(image_path)  # Save the reconstructed image to the specified path

# UI Functions for embedding
def embed():
    try:
        key = key_input.get().encode('utf-8')
        if len(key) not in [16, 24, 32]:
            raise ValueError("Key must be either 16, 24, or 32 bytes long.") #We need to input a 16, 24, 32 bit key in order to proceed
        
        # Select the input type: Text or Image
        input_type = input_type_var.get()
        
        if input_type == "Text":  # Handle the case where the input type is "Text"
            # Select the input text file
            input_file = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")]) #This ensures that when selecting a txt file, only txt files are shown for selection
            if not input_file:  # If no file is selected, exit the function
                return
            with open(input_file, 'r') as file:  #If a valid file was selected, it (r) reads its contents and removes any extra whitespace at the beginning or end with strip()
                message = file.read().strip()
            
            compressed_message = rle_compress(message)    # Compress the message using RLE (Run-Length Encoding)
            encrypted_message = encrypt_text(key, compressed_message.encode('utf-8'))  # Encrypt the compressed message using the provided key
        
        elif input_type == "Image":  # Handle the case where the input type is "Image"
            # Select the input image (any format)
            input_file = filedialog.askopenfilename(filetypes=[("Image Files", "*.jpg;*.jpeg;*.bmp;*.gif;*.png")])
            if not input_file:  # If no file is selected, exit the function
                return
            
            # Convert to PNG
            with Image.open(input_file) as img:  # Open the selected image and convert it to RGB mode
                img = img.convert("RGB")
                temp_png_path = input_file.rsplit(".", 1)[0] + "_temp.png"  # Create a temporary PNG path based on the original image file name
                img.save(temp_png_path, "PNG")   # Save the image as PNG format
            
            # Use the temporary PNG path for processing (instead of the original input file)
            binary_data, width, height = image_to_binary(temp_png_path)  # Convert the PNG image to binary data and retrieve its width and height
            compressed_data = rle_compress(binary_data) # Compress the binary data using RLE
            encrypted_message = encrypt_text(key, f"PNG_IMAGE\n{width},{height}\n{compressed_data}".encode('utf-8')) # Encrypt the data along with image dimensions and compressed binary data

        # Select the cover image (convert it to PNG)
        cover_image_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.jpg;*.jpeg;*.bmp;*.gif;*.png")])   # Open a file dialog to select the cover image (where the message will be embedded)
        if not cover_image_path:  # If no cover image is selected, exit the function
            return
        
        # Convert the cover image to PNG
        with Image.open(cover_image_path) as cover_img:  # Open the selected cover image and convert it to RGB mode
            cover_img = cover_img.convert("RGB")
            cover_temp_png = cover_image_path.rsplit(".", 1)[0] + "_cover_temp.png"  # Create a temporary PNG path for the cover image
            cover_img.save(cover_temp_png, "PNG")   # Save the cover image as PNG format
        
        # Save the output image
        output_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG Files", "*.png")])  # Open a file dialog to save the output image (after embedding the message)
        if not output_path:  # If no output path is selected, exit the function
            return
        
        # Use the converted cover image to encode the message
        encode_message(cover_temp_png, encrypted_message.hex(), output_path)  # Encode the encrypted message into the cover image and save it to the output path
        messagebox.showinfo("Success", f"Message encoded and saved to image!\nImage Location: {output_path}")  # Show a success message with the output image location
        
        #  # Clean up by deleting temporary files used during the process
        if 'temp_png_path' in locals():
            os.remove(temp_png_path) # Remove the temporary input PNG file
        os.remove(cover_temp_png) # Remove the temporary cover image PNG file

    except Exception as e:
        messagebox.showerror("Error", str(e))  # If any error occurs, show an error message with the exception details



# UI Functions for extracting
def extract():
    try:
        # Select the input image with embedded information
        image_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png")]) # Open a file dialog to select the image with embedded information
        if not image_path: # If no image is selected, exit the function
            return
        encrypted_message_hex = decode_message(image_path) # Decode the embedded message from the image
        if encrypted_message_hex: # If a message is found, proceed with decryption and decompression
            key = key_input.get().encode('utf-8')
            if len(key) not in [16, 24, 32]: # Ensure the key length is either 16, 24, or 32 bytes
                raise ValueError("Key must be either 16, 24, or 32 bytes long.")
            
            encrypted_message = bytes.fromhex(encrypted_message_hex)  # Convert the hex-encoded message back to bytes
            decrypted_message = decrypt_text(key, encrypted_message)   # Decrypt the encrypted message using the provided key
            decompressed_message = rle_decompress(decrypted_message.decode('utf-8'))  # Decompress the decrypted message using RLE (Run-Length Encoding)
            
            # Check if the extracted data is an image or text based on the identifier
            if decompressed_message.startswith("PNG_IMAGE"): # If the message is an image, extract the image data
                # It's an image, rebuild it
                decompressed_message = decompressed_message.split('\n', 2) # Split the decompressed message into components (header, dimensions, and binary data)
                width, height = map(int, decompressed_message[1].split(',')) # Extract the image width and height
                binary_data = decompressed_message[2]  # Extract the binary image data
                image_file_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG Files", "*.png")])  # Open a file dialog to save the extracted image
                if not image_file_path:    # If no save location is selected, exit the function
                    return
                
                binary_to_image(binary_data, image_file_path, width, height)  # Convert the binary data back to an image and save it
                messagebox.showinfo("Success", f"Image extracted and saved to {image_file_path}")   # Show a success message with the location of the saved image
            else:
                # It's text, save it
                output_file = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")]) # Open a file dialog to save the extracted text
                if not output_file:  # If no save location is selected, exit the function
                    return
                with open(output_file, 'w') as file:   # Write the decompressed text to the selected file
                    file.write(decompressed_message)
                messagebox.showinfo("Success", f"Message extracted and saved to text file!\nFile Location: {output_file}")# Show a success message with the location of the saved text file
        else:
            messagebox.showinfo("Error", "No message found in image!")  # If no message is found in the image, show an error message
    except Exception as e:
        messagebox.showerror("Error", str(e))  # If an error occurs, show an error message with the exception details

# Setup the main UI
root = ctk.CTk()
root.title("Integrated Steganography and Encryption System")

# Configure styles
ctk.set_appearance_mode("light")
ctk.set_default_color_theme("blue")

# Main frame with padding
frame = ctk.CTkFrame(root, width=800, height=600)
frame.pack(padx=20, pady=20)

# Encryption key input
key_input = ctk.CTkEntry(frame, placeholder_text="Enter Encryption Key", show='*')
key_input.pack(pady=10)

# Input type selection
input_type_var = ctk.StringVar(value="Text")
input_type_frame = ctk.CTkFrame(frame)
input_type_frame.pack(pady=10)

ctk.CTkRadioButton(input_type_frame, text="Text", variable=input_type_var, value="Text").pack(side="left", padx=10)
ctk.CTkRadioButton(input_type_frame, text="Image", variable=input_type_var, value="Image").pack(side="left", padx=10)

# Embed and Extract buttons
embed_button = ctk.CTkButton(frame, text="Embed Message", command=embed)
embed_button.pack(pady=10)

extract_button = ctk.CTkButton(frame, text="Extract Message", command=extract)
extract_button.pack(pady=10)

# Run the application
root.mainloop()
