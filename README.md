# Price Tracker

A web application for tracking product prices over time, scraping news, and providing users with an interactive platform to analyze price trends and discuss related news. The project is built using Vue.js for the front-end and FastAPI for the back-end.

## Features

- **Price Trend Analysis**: Visualize price changes of various products over time with interactive charts.
- **News Scraping**: Automatically scrape news related to commodity prices.
- **User Registration and Login**: Allow users to create accounts and log in, to upvote the news.
- **Generative AI for News Summarization**: Use AI to quickly summarize news content for better user understanding.

## Tech Stack

- **Front-End**: Vue.js
- **Back-End**: FastAPI
- **Database**: SQLite (development)
- **APIs and Libraries**:
  - Axios for HTTP requests
  - Chart.js for data visualization
  - Beautiful Soup for web scraping
  - OpenAI API for generative AI functions
- **Deployment**: Docker, Docker Compose

## Getting Started

### Prerequisites

- Node.js (version 14.x or higher)
- Python 3.8 or higher
- Docker and Docker Compose

### Installation

1. **Clone the Repository**

   ```bash
   git clone https://github.com/NCKU-SE-DP/price-tracker.git
   cd price-tracker
   ```
2. Run with Docker
   ```
   docker-compose up
   ```

### Usage
Open your web browser and go to http://localhost:8080 to access the frontend.
Use the navigation bar to explore features like price trend analysis, news browsing.
Go to http://localhost:8000/docs to access the backend documents.

### License
This project is licensed under the MIT License. See the [LICENSE](https://github.com/NCKU-SE-DP/price-tracker/blob/main/LICENSE) file for details.




```
pricetracker-lieofthehappiness
├─ .git
│  ├─ .probe-61860bde-6bd0-4661-97dd-a9c2707e588b
│  ├─ COMMIT_EDITMSG
│  ├─ config
│  ├─ description
│  ├─ FETCH_HEAD
│  ├─ HEAD
│  ├─ hooks
│  │  ├─ applypatch-msg.sample
│  │  ├─ commit-msg.sample
│  │  ├─ fsmonitor-watchman.sample
│  │  ├─ post-update.sample
│  │  ├─ pre-applypatch.sample
│  │  ├─ pre-commit.sample
│  │  ├─ pre-merge-commit.sample
│  │  ├─ pre-push.sample
│  │  ├─ pre-rebase.sample
│  │  ├─ pre-receive.sample
│  │  ├─ prepare-commit-msg.sample
│  │  ├─ push-to-checkout.sample
│  │  ├─ sendemail-validate.sample
│  │  └─ update.sample
│  ├─ index
│  ├─ info
│  │  └─ exclude
│  ├─ logs
│  │  ├─ HEAD
│  │  └─ refs
│  │     ├─ heads
│  │     │  ├─ develop
│  │     │  ├─ main
│  │     │  └─ refactor
│  │     │     ├─ naming-conventions
│  │     │     └─ structure
│  │     ├─ remotes
│  │     │  ├─ github-desktop-NCKU-SE-DP
│  │     │  │  ├─ develop
│  │     │  │  ├─ feature
│  │     │  │  │  └─ bar
│  │     │  │  ├─ feedback
│  │     │  │  ├─ HEAD
│  │     │  │  ├─ main
│  │     │  │  └─ refactor
│  │     │  │     ├─ comments
│  │     │  │     └─ naming-conventions
│  │     │  ├─ origin
│  │     │  │  ├─ develop
│  │     │  │  ├─ HEAD
│  │     │  │  ├─ main
│  │     │  │  └─ refactor
│  │     │  │     ├─ naming-conventions
│  │     │  │     └─ structure
│  │     │  ├─ support
│  │     │  │  ├─ main
│  │     │  │  └─ Unit0-Week1
│  │     │  └─ upstream
│  │     │     ├─ HEAD
│  │     │     ├─ main
│  │     │     └─ Unit0-Week1
│  │     └─ stash
│  ├─ objects
│  │  ├─ 00
│  │  │  └─ 2b0c29a0bce6a02d999afa84c342ffb3505a30
│  │  ├─ 02
│  │  │  └─ 03b064692ba1221c186822db92f7a50a60776c
│  │  ├─ 03
│  │  │  └─ c92f2683955b52d08ea2e008f45810cfb1271d
│  │  ├─ 05
│  │  │  ├─ 9c6124f7d924e26d43b2cd6528524c3cc54e2e
│  │  │  └─ e4df69c1c242b771cca1d0699aac7fe958e505
│  │  ├─ 08
│  │  │  ├─ 0298f71e143ba99ae5f64723fcb88824d7f391
│  │  │  └─ 6665702641e735809b2fb4dd968e4ad518cd68
│  │  ├─ 09
│  │  │  └─ d1b62981061964c391b7da6a740dfec4528eb3
│  │  ├─ 0a
│  │  │  ├─ 223c57b66114869966ff20501c6f3392941ea3
│  │  │  └─ e26936c2ed79f58a35040d132f43bbb574ea0a
│  │  ├─ 0d
│  │  │  └─ 5c8523f2a3b76b9f2b5af7c9a91995ab47cc75
│  │  ├─ 0f
│  │  │  ├─ a841fa62fd7745c31b6b93589b9d8bed15cf6f
│  │  │  └─ de2946d4b27417687b72683c297cb7d48603e5
│  │  ├─ 10
│  │  │  └─ 3da096e5b4675a350035ab1c0f4494793b64eb
│  │  ├─ 15
│  │  │  ├─ 022f99e241ab2fcb9e9122854dc9de403d4c1a
│  │  │  ├─ 71705e858535eb651dea28383e4bb6d79698fa
│  │  │  ├─ 7acc7d6cc411cdc4b1c4226fe3c86949baf599
│  │  │  └─ 8a6d998b1e51234f429940e82f2eddcbd7f16a
│  │  ├─ 17
│  │  │  └─ a828fc12052f102e2a0d79669207dec19c7256
│  │  ├─ 1e
│  │  │  └─ 361f3a5535059b64b423e2a0f20e4e120b7a28
│  │  ├─ 1f
│  │  │  └─ cd1a0b2770540a8e8c1c3cdbae68a2ce46da08
│  │  ├─ 20
│  │  │  ├─ 5140f55042f4ed8c1b17c53d373f049f309e47
│  │  │  └─ 932ef94fc21adec7ceccbf15bd2aecca491158
│  │  ├─ 23
│  │  │  └─ 7ee4749b1b41473a168f9b1a670138368a04e8
│  │  ├─ 25
│  │  │  └─ 95c542e24805c7299b0de1ced89e99b6690154
│  │  ├─ 27
│  │  │  ├─ 04e3d7ea94f5e3c771ff201f45f27a94f67944
│  │  │  └─ 54c991ecc329fad5502d72d47738a4cd276112
│  │  ├─ 28
│  │  │  └─ 975832b29dac21168e82fdd0a4b812c5b788f6
│  │  ├─ 2b
│  │  │  └─ 14948a324a7ffa6b26e434fc12c99c9f96f712
│  │  ├─ 2e
│  │  │  └─ 5f97c5a2bc45bde626e40f01415efb7a1de728
│  │  ├─ 31
│  │  │  └─ a76bc6025bcaa3bf82a36654647a3cb8e69769
│  │  ├─ 32
│  │  │  └─ 4696c21512bbb70dc901d907225531391d0a13
│  │  ├─ 33
│  │  │  ├─ 47704db9ba0c7d6ed4c16e21b336fac0e9f916
│  │  │  └─ 8da325008ab744827af9ac13d5920fe75b0a3c
│  │  ├─ 34
│  │  │  └─ f354f5dd61cff6cb395503bda548a32bfb1534
│  │  ├─ 35
│  │  │  └─ bffcc0d505b39415ad2a2c8c670e8ea1825b42
│  │  ├─ 36
│  │  │  └─ 0b91e6e806a93d49a3bbd4db5ba30a30b25242
│  │  ├─ 39
│  │  │  └─ d62fb33567baf547f708e2f16b93bd88040fa6
│  │  ├─ 3a
│  │  │  └─ effe1f82588093c5db90eabbd205b99e943569
│  │  ├─ 3b
│  │  │  └─ 51bc70e871ca95498a557ce22a46c17dc9f9a4
│  │  ├─ 3c
│  │  │  └─ 64022c2c0e7aa72c864d988d1bcabb66380389
│  │  ├─ 3d
│  │  │  ├─ 78c982e065eba615cc944ad7373ec2676cb168
│  │  │  └─ 913a68a63ee6413bbf73664341867852953ac9
│  │  ├─ 3f
│  │  │  ├─ 053da8f08f31543d364015f952a0a7daaa770c
│  │  │  └─ c6651f84f2cfc047a9b39782e6b14afb6fdadd
│  │  ├─ 40
│  │  │  └─ 60522ff22fc3a97ac036f6d862be0865eb7842
│  │  ├─ 41
│  │  │  └─ 36f5de4e92bb9272301801fa652d360056a82a
│  │  ├─ 42
│  │  │  └─ c3d3b4762470fa756c4849d39811ce6f61ef62
│  │  ├─ 45
│  │  │  └─ fe80ad7112b6b13a33a661f55ff174bba602c5
│  │  ├─ 47
│  │  │  ├─ d2b7762de66f8515766342055bcdb30f47cd7d
│  │  │  └─ f9bc2a6b75da4d9a278132c314a7ed9e3691e9
│  │  ├─ 48
│  │  │  ├─ 56ed76c25a0924d298fed5b06a4e4d4821c3a4
│  │  │  └─ 99f992d0b2cf8bd19e85de794debcf55ecec18
│  │  ├─ 49
│  │  │  └─ d56a15e849a8342ea39a004518dde48a20b0ab
│  │  ├─ 4b
│  │  │  └─ b6d8129efb3e9502841d33d08ed80dfb9f3bd0
│  │  ├─ 4c
│  │  │  └─ 5603b2f8cc9d332d7fb2cb2fa829e15dbfc0ea
│  │  ├─ 4f
│  │  │  └─ 2950ea96325f4ed9c3e788884d88806e2d292c
│  │  ├─ 50
│  │  │  └─ d609a5d2fa1634b5e5fe6d928a82a9f528ccd8
│  │  ├─ 53
│  │  │  └─ 65e6a7ffa0ac093be8ca622fe9bd92374a5aec
│  │  ├─ 54
│  │  │  └─ 475e05baffe9689d9d2e18305a2f67a2337669
│  │  ├─ 56
│  │  │  └─ cf1c4645a6977719b49163ba9c2aed15f3115b
│  │  ├─ 58
│  │  │  └─ 3183dbaeee031d191362f2829e7a174cd2084e
│  │  ├─ 59
│  │  │  └─ bda79efab73e6517164a1d3d60a551efb57115
│  │  ├─ 5c
│  │  │  └─ d804dc1e4f7fa7ddfcb5114be76d3738a3c49f
│  │  ├─ 5e
│  │  │  └─ da855e34a6b37a84bc4c1a93d4a12735febd86
│  │  ├─ 5f
│  │  │  └─ d952103b03d957d8beab25c69ec2ea3793b40e
│  │  ├─ 60
│  │  │  └─ 15e481509cf6931b00f7ee31c4d9bf1ab72aa9
│  │  ├─ 62
│  │  │  ├─ 06b2ec225477ef5c5212db583fbe8a42863db1
│  │  │  └─ 60cd983da670a94843ef6b8636216e006f24a7
│  │  ├─ 66
│  │  │  └─ 757493c199a0fc909aa36598f716fbac63541b
│  │  ├─ 67
│  │  │  └─ 274ab9c85903affc1acace5597e2934af936eb
│  │  ├─ 69
│  │  │  └─ e747e616baf3f832c0f403d0f37f7a78011c21
│  │  ├─ 6b
│  │  │  ├─ 958d3dd645d59c139497e8f8b3a1cc3e34f044
│  │  │  └─ bd7abd9e04b73fd8141d171be76ebd1ad332af
│  │  ├─ 6c
│  │  │  ├─ 3636c24a22daadcdebbcf5b9f4e9cdf09db718
│  │  │  ├─ a01ad9d65d8ff5101f663d47165db522ea2703
│  │  │  └─ e1735a0857688687a3a3b4a73e3e5cc57edbb3
│  │  ├─ 6d
│  │  │  ├─ 1c06cfeee0766c65695c7df427f408d0cd7264
│  │  │  ├─ 95d09d0a484b6890a8a9772cb2cb2ad2eb55d9
│  │  │  └─ bc19f21cb633a5622971993274b496016b5896
│  │  ├─ 6e
│  │  │  └─ 86ccebc1596a5ef9d261b84b60c018807b465f
│  │  ├─ 6f
│  │  │  └─ b48a8f46b19c18f38c8ae9b0bc8291a79117b7
│  │  ├─ 70
│  │  │  └─ 3c40b7e68b7482d16ef2b2fcd509852c5773ae
│  │  ├─ 71
│  │  │  └─ b1365d9516bbdd6ddf9bae321bd824c80fc6dd
│  │  ├─ 72
│  │  │  └─ ff8d9eadfb9dec7e8e68eb640516d98647646f
│  │  ├─ 73
│  │  │  └─ e140266987a43cf09b536e1464c9f698782dab
│  │  ├─ 75
│  │  │  ├─ 85889f376a48898e9f063088fac2f51d39def0
│  │  │  └─ a53bca3cc057bce0df03338939080fa52ee837
│  │  ├─ 76
│  │  │  └─ ced7dc6c4d252c466b2b38e37ab2075189f7d6
│  │  ├─ 77
│  │  │  ├─ 76d212979850c3869b584f0d239e4d60582f5d
│  │  │  └─ aa73e30e48202f9bf7359be3e2a2ea5616977e
│  │  ├─ 79
│  │  │  └─ 08396d3fd5f82f13d5246569c5c268733803db
│  │  ├─ 7a
│  │  │  └─ 6d2facbfcde9b6a52ae2575ede9a74508dc561
│  │  ├─ 7c
│  │  │  ├─ 4c54c13a9db0d719e7ad80edc1c8e94b636e1f
│  │  │  └─ d760cfacb5ffb754866d5fd5b35a7bfdb6bd08
│  │  ├─ 7d
│  │  │  ├─ 9ec413497bb6909e9b196bd30a3b50121a7b0f
│  │  │  ├─ bc92d8e5bf5b4ea29250e8e331515f6bbe195d
│  │  │  └─ feda233e4126285be37719cd2817babf5e8391
│  │  ├─ 7e
│  │  │  └─ 8c9f44b4eda8c1c5a2525b003b3d39a2ec55b2
│  │  ├─ 81
│  │  │  └─ 35da790d8bf2aca8c9ff4338c4d33086813b90
│  │  ├─ 83
│  │  │  └─ 8fd625422b4fe1e711b51cb59bd264c8cd8324
│  │  ├─ 85
│  │  │  └─ 616448c5c8daf602ae1e1a21a50aa2cd96c924
│  │  ├─ 87
│  │  │  ├─ a2b4f480cdbdb4813ceadfc43bf6850ec5f784
│  │  │  └─ ff99375172380f4961c07f1372b7fa84eeb5ff
│  │  ├─ 88
│  │  │  └─ a54ac0ab972b9f265c020302ae38afa8518470
│  │  ├─ 89
│  │  │  └─ befd1306111fb3b09e807005515400f267ea4d
│  │  ├─ 8a
│  │  │  ├─ db0fd6311beabf6cf9e6af2a06692ebbfe2cd9
│  │  │  └─ f5fc677a30c40ffd465647e66d4b4c3405101a
│  │  ├─ 8b
│  │  │  ├─ 967417702334e4053fd9e5716709229d4ea310
│  │  │  └─ cd53aa425059912a0f5db8bdb20c9ffa319641
│  │  ├─ 8c
│  │  │  └─ 70045abb23156b85b55675ad045b566f0800e0
│  │  ├─ 8d
│  │  │  └─ 6a1553d14a465d0ae02169f4126f0de681f855
│  │  ├─ 8e
│  │  │  └─ 6703723c0e7833df9fb6a5541b5f9da11e20d5
│  │  ├─ 8f
│  │  │  └─ 7ec84507726c957464c6644e695a210e8b5d51
│  │  ├─ 90
│  │  │  └─ 2bb49ef35b0d9794bcbeb5df3f8108529d469f
│  │  ├─ 91
│  │  │  └─ b94e312fff078ced4f00e20d137900943226fd
│  │  ├─ 93
│  │  │  ├─ e903ae6d3a8dd6a7c82909488f4156a98d7ca3
│  │  │  └─ f451a3ec80076cf7470904db1ec76b53887c56
│  │  ├─ 96
│  │  │  └─ 67cc4fc3c0541313d126fd5460fa3d71a65423
│  │  ├─ 97
│  │  │  └─ ed33eca2845e917e4c0b9ffc764f34d1b6afe2
│  │  ├─ 98
│  │  │  └─ 104c21a7dbbecbd38e48f508d60d95258f95a5
│  │  ├─ 99
│  │  │  ├─ b21c68219d3b877df1201fa7133439c01f64f7
│  │  │  └─ edb3633cf2d0afc37b1b4ba385565b87ec5f9d
│  │  ├─ 9b
│  │  │  ├─ 6c369cf00386e5e190c1d073186d17add2d243
│  │  │  └─ 99849a8902f664ac27de900800878586a2c2ce
│  │  ├─ 9c
│  │  │  └─ 55cd5441ecb29afdb3b2bf27d2d7407a68de74
│  │  ├─ 9d
│  │  │  └─ e636570057a223ebdf5320ac36d9a48193639a
│  │  ├─ 9f
│  │  │  └─ facf4d53935c7fe13fbe7e48f53041da268e2a
│  │  ├─ a0
│  │  │  └─ 7de3cd7f7da3aab223b4ad6db641a666c5c3b9
│  │  ├─ a1
│  │  │  └─ b7b2662dead305ba10e29bd158f642a4f34a5d
│  │  ├─ a3
│  │  │  └─ e7a22106ade0bb0c6f4893a0d71d635449e0c7
│  │  ├─ a4
│  │  │  ├─ ae088d6562086f0de8df6bc2549b4a5cb46acd
│  │  │  └─ e2de84d659e6b3850c41c9fb3ec02d69b9f008
│  │  ├─ a7
│  │  │  ├─ a369fcd54675b7ff8005f88c6cb770b9c74998
│  │  │  └─ f30cb8546f92772fe08ff5e0a83a42b4c5c9cb
│  │  ├─ a8
│  │  │  └─ d414aea6d60c08d620791beb4ec611cc18c252
│  │  ├─ aa
│  │  │  ├─ 81ffd3c6d6fcda58d7694fa60bc382a4d3e728
│  │  │  └─ 82f0192ebbc7fb1eda9deb2aa6a878118c9631
│  │  ├─ ab
│  │  │  └─ 11fc38e8eab138f0684e025c57403f7c85046d
│  │  ├─ ad
│  │  │  └─ 8fb19c3cf40591e348f1eadd47b0b2198a61cd
│  │  ├─ b1
│  │  │  └─ 883a7b63c345e4a2443bed3430487d9c43d447
│  │  ├─ b2
│  │  │  └─ 16709f7a6d99d343ae616d87ec32b5d66ebc85
│  │  ├─ b3
│  │  │  └─ 5d66e97f5ee2370dad9f4b31a1b56fbbfe65bd
│  │  ├─ b4
│  │  │  ├─ 753ce910d13381f11170aab3266ba87eb77228
│  │  │  └─ f55487ae2d130c2e6d2a156405100b34c76aa6
│  │  ├─ b5
│  │  │  ├─ 7a48199b71e410b2c29efbf73c3ed65624c936
│  │  │  └─ f22c24bbdf1d7f59572fb82802ebe521270189
│  │  ├─ b6
│  │  │  └─ 750ceffd763049b15d4f0f78e349e17b2874e9
│  │  ├─ b7
│  │  │  ├─ 45c994a97366eefff28dad3ff0a8b0f5fa5e56
│  │  │  └─ 4765381a8d809968fdfeafc2ebed68f498911d
│  │  ├─ bc
│  │  │  └─ 0fedc5a81301be53e736e7b472b193ccc3e5c1
│  │  ├─ be
│  │  │  ├─ d45902adee7f442b3bbd1aa00e60e1ea0405d8
│  │  │  └─ d5a6ac8f316c9ddc853fcd2fcb04784f675579
│  │  ├─ c0
│  │  │  └─ c1203af9e7faf597abe6e6442e2bf24d8726fb
│  │  ├─ c2
│  │  │  └─ 02c0fb922e2774435e1bb26f6f070b28641914
│  │  ├─ c3
│  │  │  ├─ c350619fd25d32a0e42087e4ecc6d89491c8bc
│  │  │  └─ ce48524a8271ae3318781acf2e9f5811284c21
│  │  ├─ c5
│  │  │  └─ 3ca9d3f630640fae76d3fe1bf44c02941f224f
│  │  ├─ c6
│  │  │  └─ dddc9727e301f3fb221912cf227e58b049ff1f
│  │  ├─ c9
│  │  │  ├─ 850c357e91ac8867eebea32e15df175661eef8
│  │  │  └─ cccd94d00bf0d388c32e19864cdf3e53d0eb14
│  │  ├─ ca
│  │  │  └─ 47a1da99fe2f7e7e8a178d2705245e1a27864b
│  │  ├─ ce
│  │  │  ├─ 0f2d2ec4b2aa28fb765fe3b91183f6e2a5d26e
│  │  │  └─ 7e94be3f398b59a35cccd8246a03efc13bf9e1
│  │  ├─ cf
│  │  │  ├─ 617e193f84b220bb32dc4c8c14a9b4b31ec947
│  │  │  └─ 65c7474e5cbe802556e1680ba2208d7956c246
│  │  ├─ d0
│  │  │  └─ 98468e9688ac3dab3b49dad32ece9339402502
│  │  ├─ d2
│  │  │  └─ 3bfaebfbeeb6d2add897cdf01d983660992045
│  │  ├─ d3
│  │  │  ├─ 449e0560468a44f481f372c2a8e617965ed067
│  │  │  └─ b19d8310089e04b71f6ee29b98ecf7ab0ee726
│  │  ├─ d5
│  │  │  └─ ff247cc1586cc5e7b3e18612b43c6a305212fc
│  │  ├─ d7
│  │  │  ├─ b4bdb37b0c2ee1ec0798c82c4c139138f12943
│  │  │  └─ f1a0859883bcb14c15a49d09a43e5becf31cf5
│  │  ├─ d8
│  │  │  └─ 76b8b708d28f086dfc50e0937883173a80cac5
│  │  ├─ d9
│  │  │  └─ fa1cd9af7c0c7d7652ad37528f314267669666
│  │  ├─ da
│  │  │  └─ 74ad657ebf9c8f6169cf9eed79e500ecd59c08
│  │  ├─ de
│  │  │  ├─ 9125a110e50c9a05a69e66104a7e0a62aec686
│  │  │  └─ ed2333709d62fe1c908dd29fc72272baa41d35
│  │  ├─ df
│  │  │  └─ 2a629a43b8480de643dbb784fc26055833c494
│  │  ├─ e0
│  │  │  └─ 7a84d58fb02aa84134eca68b67478b98de7745
│  │  ├─ e3
│  │  │  ├─ 672e6e50b93147811a68790956adbaa7d22d14
│  │  │  ├─ 9285d83450b443390dd773dc9bef130784f4f2
│  │  │  └─ f914111b0397b9b0431d36bba507ba326f33c9
│  │  ├─ e7
│  │  │  └─ 34494a9a3927ed25196932cacf2a03cced5c74
│  │  ├─ e9
│  │  │  └─ f175e67b7fc11877593e35c38c750917049dc6
│  │  ├─ eb
│  │  │  └─ 483eacf9c1fdf59d080eb57a3899e2ec951214
│  │  ├─ ec
│  │  │  └─ 5bd7a016e358a953fa5f8473b89f05f9cb7672
│  │  ├─ ed
│  │  │  └─ ac470cafd906ded824c177da2d7022734fcc68
│  │  ├─ ef
│  │  │  └─ ec0cffec003cbda95ae7f8736e1d4c536389cc
│  │  ├─ f0
│  │  │  ├─ 2f5d5df59f8fb6350a73fac0ce8f9568f89dfc
│  │  │  ├─ b405f61d292bc1c53586743bfa5b6dbf45898e
│  │  │  ├─ f4d6b5ef9bda9a29ab311babc496c552cacb3c
│  │  │  └─ fa933a8a208416920c726d68236ee0053e6a63
│  │  ├─ f2
│  │  │  └─ a53757e81ff00cdc9f56bb6d2fbe07904b2b49
│  │  ├─ f4
│  │  │  └─ f66d41fd517392dda4d7241f8814aef2f6b092
│  │  ├─ f5
│  │  │  └─ 9a18a5c176ccc1a9e368155b5b7f0bc64588e0
│  │  ├─ f7
│  │  │  └─ 5484fb51232ef306bc5aa2d5bdb51493a35864
│  │  ├─ f8
│  │  │  ├─ 44a944e1392560b7779ff4d3885350d27e44c4
│  │  │  └─ bd21452bd40e8ed0ae23c3a7ff7cb487d4f871
│  │  ├─ f9
│  │  │  └─ 554c9da73dbc36e2b59251cce298937c7b58af
│  │  ├─ fb
│  │  │  └─ 38f185aa8db170ff514440108cc014f5285b11
│  │  ├─ fd
│  │  │  ├─ 88c4d80612d1eba1b6e2ee8f2f02092ca0ddc4
│  │  │  └─ 8b3ea0daba0bb02ee233448d5d6e107b091b68
│  │  ├─ fe
│  │  │  └─ 57f02234c438aee72168aa810fcc70d46ab22a
│  │  ├─ info
│  │  └─ pack
│  │     ├─ pack-7f01a023e9b163d0d8ed6aa4c1543605986639a3.idx
│  │     ├─ pack-7f01a023e9b163d0d8ed6aa4c1543605986639a3.pack
│  │     ├─ pack-7f01a023e9b163d0d8ed6aa4c1543605986639a3.rev
│  │     ├─ pack-ebb5842bdeb35802c145032515b385a3431f49c7.idx
│  │     ├─ pack-ebb5842bdeb35802c145032515b385a3431f49c7.pack
│  │     └─ pack-ebb5842bdeb35802c145032515b385a3431f49c7.rev
│  ├─ ORIG_HEAD
│  ├─ packed-refs
│  └─ refs
│     ├─ heads
│     │  ├─ develop
│     │  ├─ main
│     │  └─ refactor
│     │     ├─ naming-conventions
│     │     └─ structure
│     ├─ remotes
│     │  ├─ github-desktop-NCKU-SE-DP
│     │  │  ├─ develop
│     │  │  ├─ feature
│     │  │  │  └─ bar
│     │  │  ├─ feedback
│     │  │  ├─ HEAD
│     │  │  ├─ main
│     │  │  └─ refactor
│     │  │     ├─ comments
│     │  │     └─ naming-conventions
│     │  ├─ origin
│     │  │  ├─ develop
│     │  │  ├─ HEAD
│     │  │  ├─ main
│     │  │  └─ refactor
│     │  │     ├─ naming-conventions
│     │  │     └─ structure
│     │  ├─ support
│     │  │  ├─ main
│     │  │  └─ Unit0-Week1
│     │  └─ upstream
│     │     ├─ HEAD
│     │     ├─ main
│     │     └─ Unit0-Week1
│     ├─ stash
│     └─ tags
├─ .github
│  ├─ .keep
│  └─ workflows
│     └─ ci.yaml
├─ .gitignore
├─ backend
│  ├─ alembic
│  │  ├─ env.py
│  │  ├─ README
│  │  └─ script.py.mako
│  ├─ alembic.ini
│  ├─ dockerfile
│  ├─ news_database.db
│  ├─ pytest.ini
│  ├─ Readme.md
│  ├─ requirements.txt
│  ├─ src
│  │  ├─ auth
│  │  │  ├─ config.py
│  │  │  ├─ schemas.py
│  │  │  ├─ services.py
│  │  │  └─ utils.py
│  │  ├─ config.py
│  │  ├─ database.py
│  │  ├─ main.py
│  │  ├─ models.py
│  │  ├─ news
│  │  │  ├─ config.py
│  │  │  ├─ router.py
│  │  │  ├─ schemas.py
│  │  │  └─ utils.py
│  │  ├─ prices
│  │  │  ├─ constants.py
│  │  │  └─ router.py
│  │  ├─ README.md
│  │  └─ users
│  │     ├─ constants.py
│  │     └─ router.py
│  └─ tests
│     ├─ integration
│     │  ├─ test_news_endpoint.py
│     │  ├─ test_price_endpoint.py
│     │  └─ test_user_endpoint.py
│     └─ __init__.py
├─ docker-compose.yml
├─ frontend
│  ├─ .gitignore
│  ├─ babel.config.js
│  ├─ dockerfile
│  ├─ jsconfig.json
│  ├─ node_modules
│  ├─ package-lock.json
│  ├─ package.json
│  ├─ public
│  │  ├─ favicon.ico
│  │  └─ index.html
│  ├─ README.md
│  ├─ src
│  │  ├─ App.vue
│  │  ├─ assets
│  │  │  ├─ logo.png
│  │  │  └─ reset.css
│  │  ├─ components
│  │  │  ├─ CategoryPrice.vue
│  │  │  ├─ NavBar.vue
│  │  │  ├─ NewsDialog.vue
│  │  │  ├─ NewsItem.vue
│  │  │  ├─ TrendingChart.vue
│  │  │  └─ TrendingTable.vue
│  │  ├─ constants
│  │  │  └─ categories.js
│  │  ├─ main.js
│  │  ├─ pages
│  │  │  ├─ NewsList.vue
│  │  │  ├─ PriceOverview.vue
│  │  │  ├─ PriceTrending.vue
│  │  │  ├─ UserLogin.vue
│  │  │  └─ UserRegister.vue
│  │  ├─ router
│  │  │  └─ index.js
│  │  └─ stores
│  │     ├─ auth.js
│  │     ├─ news.js
│  │     └─ prices.js
│  ├─ vue.config.js
│  └─ your-local-directory
├─ LICENSE
└─ README.md

```