const host = import.meta.env.REACT_APP_API_HOST || "http://localhost:8001";
console.log("host:", host);
export const API_BASE_URL = `${host}/api/v1`;

import axios from "axios";

// API request function
const apiRequest = async (url, method, body = null) => {
  console.log("url:", url, "method:", method, "body:", body);
  const accessToken = sessionStorage.getItem("accessToken");
  console.log("accessToken:", accessToken);
  const options = {
    method,
    url: `${API_BASE_URL}${url}`,
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${accessToken}`,
    },
    withCredentials: true,
    data: body,
  };

  try {
    const response = await axios(options);
    return response.data;
  } catch (error) {
    console.error("API Request Error:", error);
    if (error.response) {
      throw new Error(
        `HTTP error! status: ${error.response.status}, message: ${
          error.response.data.message || "Unknown error"
        }`
      );
    }
    throw error;
  }
};

// API functions
// User
export const registerAPI = (data) => apiRequest("/auth/register", "POST", data);
export const loginAPI = (data) => {
  console.log("Calling login API with data:", data); // Log the data being sent
  return apiRequest("/auth/login", "POST", data);
};

// Quiz
export const createQuiz = (quizData) =>
  apiRequest("/quiz/createQuiz", "POST", quizData);
export const getAllQuizzes = () => apiRequest("/quiz/getAllQuizzes", "GET");
export const getQuizById = (quizId) =>
  apiRequest(`/quiz/getQuiz/${quizId}`, "GET");
export const updateQuiz = (quizId, quizData) =>
  apiRequest(`/quizzes/updateQuiz/${quizId}`, "PUT", quizData);
export const deleteQuiz = (quizId) =>
  apiRequest(`/quiz/deleteQuiz/${quizId}`, "DELETE");
// export const publishQuiz = (quizId) => apiRequest(`/quiz/publish/${quizId}`, 'POST');

// Question
export const addQuestion = (questionData) =>
  apiRequest(`/quiz/createQuestion`, "POST", questionData);
export const getAllQuestionsByQuiz = (quizId) =>
  apiRequest(`/quiz/quizzes/${quizId}`, "GET");
export const getQuestionById = (questionId) =>
  apiRequest(`/quiz/questions/${questionId}`, "GET");
export const updateQuestion = (questionId, questionData) =>
  apiRequest(`/quiz/updateQuestion/${questionId}`, "PUT", questionData);
// export const deleteQuestion = (questionId) => apiRequest(`/quiz/deleteQuestion/${questionId}`, 'DELETE');
export const duplicateQuestion = (questionId) =>
  apiRequest(`/quiz/questions/${questionId}/duplicate`, "POST");

// DELETE QUESTION -- no body reqd for deleting
export const deleteQuestion = async (questionId) => {
  try {
    const response = await axios.delete(
      `${API_BASE_URL}/quiz/deleteQuestion/${questionId}`
    );
    console.log(response);
    return response.data;
  } catch (error) {
    console.error(
      "Error deleting question:",
      error.response ? error.response.data : error.message
    );
    throw error;
  }
};

export const publishQuiz = async (quizId) => {
  try {
    const response = await axios.post(`${API_BASE_URL}/quiz/publish/${quizId}`);
    console.log(response);
    return response.data;
  } catch (error) {
    console.error(
      "Error publishing quiz:",
      error.response ? error.response.data : error.message
    );
    throw error;
  }
};
