import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import { User } from "../models/user.model.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import jwt from "jsonwebtoken"
import mongoose from "mongoose";




const generateAccessAndRefereshTokens = async (userId) => {
    try {
        const user = await User.findById(userId)
        const accessToken = user.generateAccessToken()
        const refreshToken = user.generateRefreshToken()

        user.refreshToken = refreshToken        // here we directly asiging the value in Database user.password = newPassword
        await user.save({ validateBeforeSave: false })  // here we saving the new value to dabase enntry user.save({this the you need any validation before save})

        return { accessToken, refreshToken }


    } catch (error) {
        throw new ApiError(500, "Something went wrong while generating referesh and access token")
    }
}

const registerUser = asyncHandler(async (req, res) => {
    // get user details from frontend
    // validation - not empty
    // check if user already exists: username, email
    // check for images, check for avatar
    // upload them to cloudinary, avatar
    // create user object - create entry in db
    // remove password and refresh token field from response
    // check for user creation
    // return res


    const { fullName, email, username, password } = req.body
    //console.log("email: ", email);

    if (
        [fullName, email, username, password].some((field) => field?.trim() === "")
    ) {
        throw new ApiError(400, "All fields are required")
    }

    const existedUser = await User.findOne({
        $or: [{ username }, { email }]
    })

    if (existedUser) {
        throw new ApiError(409, "User with email or username already exists")
    }
    //console.log(req.files);

    const avatar = req.files?.avatar[0]?.path;

    if (!avatar) {
        throw new ApiError(400, "Avatar file is required")
    }


    const user = await User.create({
        fullName,
        avatar,
        email,
        password,
        username: username.toLowerCase()
    })

    const createdUser = await User.findById(user._id).select(
        "-password -refreshToken"
    )

    if (!createdUser) {
        throw new ApiError(500, "Something went wrong while registering the user")
    }

    return res.status(201).json(
        new ApiResponse(200, createdUser, "User registered Successfully")
    )

})

const loginUser = asyncHandler(async (req, res) => {
    // req body -> data
    // username or email
    //find the user
    //password check
    //access and referesh token
    //send cookie

    const { email, username, password } = req.body
    console.log(email);

    if (!username && !email) {
        throw new ApiError(400, "username or email is required")
    }

    // Here is an alternative of above code based on logic discussed in video:
    // if (!(username || email)) {
    //     throw new ApiError(400, "username or email is required")

    // }

    const user = await User.findOne({
        $or: [{ username }, { email }]
    })

    if (!user) {
        throw new ApiError(404, "User does not exist")
    }

    const isPasswordValid = await user.isPasswordCorrect(password)

    if (!isPasswordValid) {
        throw new ApiError(401, "Password invalid")
    }

    console.log(isPasswordValid)   // it give true or false value

    const { accessToken, refreshToken } = await generateAccessAndRefereshTokens(user._id)

    const loggedInUser = await User.findById(user._id).select("-password -refreshToken")

    const options = {
        httpOnly: true,    //  this for only cookies modified at sever site but can't modified at frontend
        secure: true      // this foe secure
    }                    //when we use cookie we have to create option

    return res
        .status(200)
        .cookie("accessToken", accessToken, options) //we sending cookie ("name",value,options) name that value , what is value , options is what in side
        .cookie("refreshToken", refreshToken, options) //we sending cookie ("name",value,options) name that value , what is value , options is what in side
        .json(
            new ApiResponse(
                200,
                {
                    user: loggedInUser, accessToken, refreshToken
                },
                "User logged In Successfully"
            )
        )

})

const logoutUser = asyncHandler(async (req, res) => {
    await User.findByIdAndUpdate(
        req.user._id,
        {
            $set: {
                refreshToken: undefined
            }
        },
        {
            new: true
        }
    )

    const options = {
        httpOnly: true,
        secure: true
    }

    return res
        .status(200)
        .clearCookie("accessToken", options)
        .clearCookie("refreshToken", options)
        .json(new ApiResponse(200, {}, "User logged Out"))
})

const refreshAccesstoken = asyncHandler(async (req, res) => {
    const incomingRefreshtoken = req.cookie.refreshToken || req.body.refreshToken  // this coming from user computer so its encrypted

    if (!incomingRefreshtoken) {
        throw new ApiError(401, "invalid access token")
    }

    try {
        const decodedToken = jwt.verify(incomingRefreshtoken, process.env.REFRESH_TOKEN_SECRET)

        const user = User.findById(decodedToken._id)

        if (!user) {
            throw new ApiError(401, "invalid access token")
        }

        if (incomingRefreshtoken !== user?.refreshToken) {
            throw new ApiError(401, "Refresh Token is invalid")
        }

        const options = {
            httpOnly: true,
            secure: true
        }

        const { accessToken, newRefreshToken } = await generateAccessAndRefereshTokens(user._id)

        return res
            .status(200)
            .cookie("accessToken", accessToken, options)
            .cookie("refreshToken", newRefreshToken, options)
            .json(
                new ApiResponse(
                    200,
                    { accessToken, refreshToken: newRefreshToken },
                    "Access token refreshed"
                )
            )
    } catch (error) {
        throw new ApiError(
            400, error?.message
        )
    }

})

const changeCurrentPassword = asyncHandler(async (req, res) => {

    const { oldPassword, newPassword } = req.body

    const user = await User.findById(req.user?._id)

    const isPasswordCorrect = await user.isPasswordCorrect(oldPassword)

    if (!isPasswordCorrect) {
        throw new ApiError(401, "invalid old password")
    }

    user.password = newPassword              // here we directly asiging the value in Database user.password = newPassword

    await user.save({ validateBeforeSave: false }) // here we saving the new value to dabase enntry user.save({this the you need any validation before save})

    return res
        .status(200)
        .json(new ApiResponse(200, {}, "Password change succesfull"))

})

const getCurrentUser = asyncHandler(async (req, res) => {
    return res
        .status(200)
        .json(new ApiResponse(200, req.user, "current user fetched"))
})

const updateAccountDetails = asyncHandler(async (req, res) => {

    const { fullName, email , username} = req.body

    if (!(fullName || email || username)) {
        throw new ApiError(400, "All field are requried")
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set: {
                fullName,   //this method is also fine
                email: email , // this method also fine
                username
            }
        },
        {
            new: true
        }
    ).select("-password")

    return res
        .status(200)
        .json(new ApiResponse(200, user, "Account details update succesfully"))
})

const updateUserAvatar = asyncHandler(async (req, res) => {

    const avatar = req.file?.path
    
    if(!avatar){
        throw new ApiError(400,"avatar file is missing")
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set:{
                avatar : avatar
            }
        },
        {
            new:true
        }.select("-password")
    )
   
    return res
    .status(200)
    .json(
        new ApiResponse(
            200,
            user,
            "Avatar image updated successfully"
        )
    )

})

const getUserChannelProfile = asyncHandler(async (req,res) => {

    const {username} = req.params

    if(!username?.trim()){
        throw new ApiError(400,"username is missing")
    }

    const channel = await User.aggregate([
        {
            $match:{
                username:username?.toLowerCase()
            }
        },
        {
            $lookup:{
                from:"subscriptions",       // In the database its gone be plural and lowercase   and its Subcsription schema 
                localField:"_id",
                foreignField:"channel",
                as:"subscribers"

            }
        },
        {
            $lookup:{                        // this is for Subscriber 
                from:"subscriptions",
                localField:"_id",
                foreignField:"subscriber",
                as:"subscribedTo"
            }
        },
        {
            $addFields:{                  //this two Things add in User Schema
                 subscriberCount:{
                    $size: "$subscribers"           // we add $ bcoz now the as:"subscribers" this is a Field
                 },
                 channelSubscribedTocount:{
                    $size:"$subscribedTo"
                 }
            }
        },
        {
            isSubscribed:{
                $cond:{
                    if:{$in:[req.user?._id,"subscribers.subscriber"]},
                    then:true,
                    else:false
                }
            }
        },
        {
            $project:{              // this is for data send 
                fullName:1,         // nwhichfield show=true/false        1 mean show the data of fullName
                username:1,
                subscriberCount:1,
                channelSubscribedTocount:1,
                isSubscribed:1,
                email:1,
            }
        }
    ])

    if(!channel?.length){
        throw new ApiError(401,"Channel does not exist")
    }

    return res
    .status(200)
    .json(
        new ApiResponse(200,channel[0],'user chanel Fetched')
    )

    

})


const getWatchHistory = asyncHandler(async(req,res) => {

       const user = await User.aggregate([
        {
            $match:{
                _id:new mongoose.Types.ObjectId(req.user._id)   // agragate code goes dirctly so convert throught mongoose
            },
        },
        {
            $lookup:{
                from:"videos",
                localField:"watchHistory",
                foreignField:"_id",
                as:"watchHistory",
                pipeline:[                       //nested pipeline bcoz of i want thats video owner information
                     {
                        $lookup:{
                            from:"users",
                            localField:"owner",
                            foreignField:"_id",
                            as:"owner",
                            pipeline:[
                                {
                                    $project:{                    
                                        userName:1,
                                        email:1,
                                        username:1
                                    }
                                },
                                {
                                    $addFields:{                      // we write bcoz it will return array so directly send object of first
                                        owner:{
                                            $first:"$owner"           
                                        }
                                    }
                                }
                            ]
                        }
                     }
                ]
            }
        }
       ])

       return res
       .status(200)
       .json(
        new ApiResponse(200,user[0].watchHistory,"watch history Fetched")
       )

})




export { registerUser, loginUser, logoutUser, refreshAccesstoken, changeCurrentPassword, getCurrentUser, updateAccountDetails, updateUserAvatar, getUserChannelProfile, getWatchHistory}