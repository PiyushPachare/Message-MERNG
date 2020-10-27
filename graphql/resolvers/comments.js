const { AuthenticationError, UserInputError } = require("apollo-server");

const Post = require("../../models/Post");
const checkAuth = require("../../util/checkAuth");

module.exports = {
  Mutation: {
    //create comment
    async createComment(_, { postId, body }, context) {
      const { username } = checkAuth(context);

      if (body.trim() === "") {
        throw new UserInputError("Empty comment", {
          errors: {
            body: "Comment body must not empty",
          },
        });
      }

      const post = await Post.findById(postId);

      if (post) {
        post.comments.unshift({
          body,
          username,
          createdAt: new Date().toISOString(),
        });
        await post.save();
        return post;
      } else throw new UserInputError("Post not found");
    },

    //delete comment
    async deleteComment(_, { postId, commentId }, context) {
      const { username } = checkAuth(context);

      const post = await Post.findById(postId);

      if (post) {
        const commentIndex = post.comments.findIndex((c) => c.id === commentId);

        if (post.comments[commentIndex].username === username) {
          post.comments.splice(commentIndex, 1);
          await post.save();
          return post;
        } else {
          throw new AuthenticationError("Action not allowed");
        }
      } else {
        throw new UserInputError("Post Not Found");
      }
    },
    //like post
    async likePost(_, { postId }, context) {
      const { username } = checkAuth(context);

      const post = await Post.findById(postId);
      if (post) {
        if (post.likes.find((like) => like.username === username)) {
          //POst alredy liked
          post.likes = post.likes.filter((like) => like.username !== username);
          await post.save();
        } else {
          //not liked
          post.likes.push({
            username,
            createdAt: new Date().toISOString(),
          });
        }

        await post.save();
        return post;
      } else throw UserInputError("Post not found");
    },
  },
};
