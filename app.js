import express from "express";
import mongoose from "mongoose";
import 'dotenv/config';
import bcrypt from "bcrypt";
import { nanoid } from "nanoid";
import jwt from "jsonwebtoken";
import cors from "cors";
import admin from "firebase-admin";
import User from "./Schema/User.js";
import Blog from "./Schema/Blog.js";
import { getAuth } from "firebase-admin/auth";
import cloudinary from 'cloudinary';
import { CloudinaryStorage } from 'multer-storage-cloudinary';
import multer from 'multer';

const serviceAccountKey = {
    type: process.env.FIREBASE_TYPE,
    project_id: process.env.FIREBASE_PROJECT_ID,
    private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
    private_key: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'),
    client_email: process.env.FIREBASE_CLIENT_EMAIL,
    client_id: process.env.FIREBASE_CLIENT_ID,
    auth_uri: process.env.FIREBASE_AUTH_URI,
    token_uri: process.env.FIREBASE_TOKEN_URI,
    auth_provider_x509_cert_url: process.env.FIREBASE_AUTH_PROVIDER_X509_CERT_URL,
    client_x509_cert_url: process.env.FIREBASE_CLIENT_X509_CERT_URL,
    universe_domain: process.env.FIREBASE_UNIVERSE_DOMAIN,
  };

admin.initializeApp({
    credential: admin.credential.cert(serviceAccountKey),
})

cloudinary.v2.config({
  cloud_name: process.env.CLOUDINARY_NAME,
  api_key: process.env.CLOUDINARY_KEY,
  api_secret: process.env.CLOUDINARY_SECRET,
});

const storage = new CloudinaryStorage({
  cloudinary: cloudinary.v2,
  allowedFormats: ["jpg", "png", "jpeg"],
  params: {
    folder: "my-blog",
  },
});

const uploadCloud = multer({ storage });

let emailRegex = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/; // regex for email
let passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,20}$/; // regex for password

const app = express();

mongoose.connect(process.env.MONGODB_URI, {
    autoIndex: true,
})

const corsOptions = {
    origin: 'https://my-blog-client-inky.vercel.app',
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    credentials: true,
  };
  
app.use(cors(corsOptions));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));


app.get('/', (req, res) => {
    res.send('Hello, Vercel!');
  });

const verifyJWT = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(" ")[1];

    if(token == null) {
        return res.status(401).json({ "error": "No access token" });
    }

    jwt.verify(token, process.env.JWT_SECRET_ACCESS_KEY, (err, user) => {
        if(err) {
            return res.status(403).json({ "error": "Invalid access token" });
        }

        req.user = user.id;
        next();
    })
}

const formatDataToSend = (user) => {
    const access_token = jwt.sign({ id: user._id }, process.env.JWT_SECRET_ACCESS_KEY, { expiresIn: "1h" });

    return {
        access_token,
        profile_img: user.personal_info.profile_img,
        username: user.personal_info.username,
        fullname: user.personal_info.fullname,
    }
}

const generateUsername = async(email) => {
    let username = email.split("@")[0];

    let isUsernameExists = await User.exists({"personal_info.username": username}).then((result) => result)

    isUsernameExists ? username += nanoid().substring(0, 5) : "";

    return username;
}

app.post("/api/v1/auth/sign-up", (req, res) => {
    let { fullname, email, password } = req.body;

    if(fullname.length < 3) {
        return res.status(403).json({"error": "Fullname must be at least 3 characters long"});
    }
    if(!email.length) {
        return res.status(403).json({"error": "Email is required"});
    }
    if(!emailRegex.test(email)) {
        return res.status(403).json({"error": "Invalid email"});
    }
    if(!passwordRegex.test(password)) {
        return res.status(403).json({"error": "Password should be 6 to 20 characters long with a numeric, 1 lowercase and 1 uppercase letters"});
    }

    bcrypt.hash(password, 10, async (err, hashed_password) => {
        let username = await generateUsername(email);

        let user = new User({
            personal_info: { fullname, email, password: hashed_password, username }
        })

        user.save().then((u) => {
            return res.status(200).json(formatDataToSend(u));
        })
        .catch((err) => {
            if(err.code === 11000) {
                return res.status(500).json({ "error": "Email is already in use" });
            }

            return res.status(500).json({ "error": err.message });
        })

        console.log(hashed_password);
    })
})

app.post("/api/v1/auth/sign-in", (req, res) => {
    let { email, password } = req.body;
    User.findOne({ "personal_info.email": email})
    .then((user) => {
        if(!user) {
            return res.status(403).json({ "error": "Email not found"})
        }

        if(!user.google_auth) {
            bcrypt.compare(password, user.personal_info.password, (err, result) => {
                if(err) {
                    return res.status(403).json({ "error": "Error occurred while logging in, please try again." });
                }
                if(!result) {
                    return res.status(403).json({ "error": "Incorrect password"})
                } else {
                    return res.status(200).json(formatDataToSend(user));
                }
            })
        } else {
            return res.status(403).json({ "error": "This email was signed up with google. Please log in with google to access the account" });
        }
    })
    .catch((error) => {
        console.log(error.message);
        return res.status(500).json({ "error": error.message})
    })
})

app.post("/api/v1/auth/google-auth", async (req, res) => {
    let { access_token } = req.body;
    getAuth()
    .verifyIdToken(access_token)
    .then(async (decodedUser) => {
        let { email, name, picture } = decodedUser;

        picture = picture.replace("s96-c", "s384-c");

        let user = await User.findOne({ "personal_info.email": email }).select("personal_info.fullname personal_info.username personal_info.profile_img google_auth").then((u) => {
            return u || null;
        })
        .catch(error => {
            return res.status(500).json({ "error": error.message });
        });

        if(user) { //login
            if(!user.google_auth) {
                return res.status(403).json({ "error": "This email was signed up without google. Please log in with password to access the account" });
            }
        } else {    //sign up
            let username = await generateUsername(email);
            user = new User({
                personal_info: { fullname: name, email, profile_img: picture, username },
                google_auth: true
            })
    
            await user.save().then((u) => {
                user = u;
            })
            .catch(err => {
                return res.status(500).json({ "error": err.message });
            })
        }
        return res.status(200).json(formatDataToSend(user));
    })
    .catch(error => {
        return res.status(500).json({ "error": "Failed to authenticate tou with google. Try with some other google account" });
    })
    
})

app.post('/api/v1/upload-image', uploadCloud.single('image'), async (req, res) => {
    try {
      // File đã được upload lên Cloudinary, thông tin lưu trong req.file
      if (!req.file) {
        return res.status(400).json({ message: 'No image file uploaded' });
      }
  
      const uploadedImage = req.file.path; // URL của ảnh đã upload
      res.status(200).json({
        message: 'Image uploaded successfully',
        imageUrl: uploadedImage,
      });
    } catch (error) {
      console.error('Error uploading image:', error);
      res.status(500).json({ message: 'Failed to upload image', error });
    }
  });

app.post('/api/v1/search-blogs-count', (req, res) => {
    let { tag, author, query } = req.body;
    let findQuery;

    if(tag) {
        findQuery = { tags: tag, draft: false };
    } else if (query) {
        findQuery = { draft: false, title: new RegExp(query, 'i')}
    } else if (author) {
        findQuery = { author, draft: false };
    }

    Blog.countDocuments(findQuery)

    .then(count => {
        return res.status(200).json({ totalDocs: count })
    })
    .catch(err => {
        console.log(err.message);
        return res.status(500).json({error: err.message});
    })

})

app.post('/api/v1/latest-blogs', (req, res) => {
    let { page } = req.body;
    let maxLimit = 5;

    Blog.find({ draft: false })
    .populate("author", "personal_info.profile_img personal_info.username personal_info.fullname -_id")
    .sort({ "publishedAt": -1})
    .select("blog_id title des banner activity tags publishedAt -_id")
    .skip((page - 1) * maxLimit)
    .limit(maxLimit)
    .then(blogs => {
        return res.status(200).json({blogs});
    })
    .catch(err => {
        return res.status(500).json({ error: err.message });
    })
})

app.post('/api/v1/all-latest-blogs-count', (req, res) => {
    Blog.countDocuments({ draft: false })
    .then(count => {
        return res.status(200).json({ totalDocs: count })
    })
    .catch(err => {
        console.log(err.message);
        return res.status(500).json({error: err.message});
    })
})

app.get('/api/v1/trending-blogs', (req, res) => {
    Blog.find({draft: false})
    .populate("author", "personal_info.profile_img personal_info.username personal_info.fullname -_id")
    .sort({"activity.total_read": -1, "activity.total_likes": -1, "publishedAt": -1})
    .select("blog_id title publishedAt -_id")
    .limit(5)
    .then(blogs => {
        return res.status(200).json({blogs})
    })
    .catch(err => {
        return res.status(500).json({ error: err.message });
    })
})

app.post('/api/v1/search-blogs', (req, res) => {
    let { tag, query, author, page, limit, eliminate_blog } = req.body;
    let findQuery;
    
    if(tag) {
        findQuery = { tags: tag, draft: false, blog_id: { $ne: eliminate_blog} };
    } else if (query) {
        findQuery = { draft: false, title: new RegExp(query, 'i')}
    } else if (author) {
        findQuery = { author, draft: false };
    }

    let maxLimit = limit ? limit : 2;

    Blog.find(findQuery)
    .populate("author", "personal_info.profile_img personal_info.username personal_info.fullname -_id")
    .sort({"activity.total_read": -1, "activity.total_likes": -1, "publishedAt": -1})
    .select("blog_id title des banner activity tags publishedAt -_id")
    .skip((page - 1) * maxLimit)
    .limit(maxLimit)
    .then(blogs => {
        return res.status(200).json({blogs})
    })
    .catch(err => {
        return res.status(500).json({ error: err.message });
    })
})

app.post('/api/v1/get-blog', (req, res) => {
    let { blog_id, draft, mode } = req.body;
    let incrementVal = mode != 'edit' ? 1 : 0;

    Blog.findOneAndUpdate({ blog_id }, { $inc: {"activity.total_reads": incrementVal}})
    .populate("author", "personal_info.fullname personal_info.username personal_info.profile_img")
    .select("title des content banner activity publishedAt blog_id tags")
    .then(blog => {
        User.findOneAndUpdate({ "personal_info.username": blog.author.personal_info.username}, {
            $inc: {"account_info.total_reads": incrementVal}
        })
        .catch(err => {
            return res.status(500).json({error: err.message})
        })

        if(blog.draft && !draft) {
            return res.status(500).json({error: 'you cannot access draft blog' })
        }
        return res.status(200).json({blog})
    })
    .catch(err => {
        return res.status(500).json({ error: err.message })
    })
})

app.post('/api/v1/create-blog', verifyJWT, (req, res) => {
    let authorId = req.user;

    let { title, des, banner, tags, content, draft, id } = req.body.blogData;
    
    console.log({ title, des, banner, tags, content, draft, id });

    if(!title.length) {
        return res.status(403).json({ error: "You must provide a title" });
    }

    if(!draft) {
        if(!des.length || des.length > 200) {
            return res.status(403).json({ error: "You must provide blog description under 200 characters" });
        }
    
        if(!banner.length) {
            return res.status(403).json({ error: "You must provide blog banner to publish the blog" });
        }
    
        if(!content.blocks.length) {
            return res.status(403).json({ error: "There must be at some blog content to publish it" });
        }
    
        if(!tags.length || tags.length > 10) {
            return res.status(403).json({ error: "Provide tags in order to publish the blog, Maximum is 10" });
        }
    }

    tags = tags.map(tag => tag.toLowerCase());

    let blog_id = id || title.replace(/[^a-zA-Z0-9]/g,' ').replace(/\s+/g, "-").trim() + nanoid();

    if (id) {
        Blog.findOneAndUpdate({blog_id}, {title, des, banner, content, tags, draft: draft ? draft : false})
        .then(() => {
            return res.status(200).json({ id: blog_id })
        })
        .catch(err => {
            return res.status(500).json({ error: err.message })
        })
    } else {
      let blog = new Blog({
        title,
        des,
        banner,
        content,
        tags,
        author: authorId,
        blog_id,
        draft: Boolean(draft),
      });

      blog
        .save()
        .then((blog) => {
          let incrementVal = draft ? 0 : 1;

          User.findOneAndUpdate(
            { _id: authorId },
            {
              $inc: { "account_info.total_posts": incrementVal },
              $push: { blogs: blog._id },
            }
          )
            .then((user) => {
              return res.status(200).json({ id: blog.blog_id });
            })
            .catch((err) => {
              return res
                .status(500)
                .json({ error: "Failed to update total posts number" });
            });
        })
        .catch((err) => {
          return res.status(500).json({ error: err.message });
        });
    }

    

})

app.post('/api/v1/search-users', (req, res) => {
    let { query } = req.body

    User.find({"personal_info.username": new RegExp(query, 'i')})
    .limit(50)
    .select("personal_info.fullname personal_info.username personal_info.profile_img -_id")
    .then(users => {
        return res.status(200).json({ users })
    })
    .catch(err => {
        return res.status(500).json({ error: err.message })
    })
})

app.post('/api/v1/get-profile', (req, res) => {
    let { username } = req.body;
    
    User.findOne({ "personal_info.username": username })
    .select("-personal_info.password -google_auth -updateAt -blogs")
    .then(user => {
        return res.status(200).json(user);
    })
    .catch(err => {
        console.log(err);
        return res.status(500).json({ error: err.message });
    })
})


export default app;